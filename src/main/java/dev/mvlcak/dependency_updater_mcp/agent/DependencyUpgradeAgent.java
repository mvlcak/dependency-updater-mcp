package dev.mvlcak.dependency_updater_mcp.agent;


import com.embabel.agent.api.annotation.*;
import com.embabel.agent.api.common.Ai;
import com.embabel.agent.api.common.OperationContext;
import com.embabel.agent.domain.io.UserInput;
import dev.mvlcak.dependency_updater_mcp.domain.*;
import dev.mvlcak.dependency_updater_mcp.osv.OsvClient;
import dev.mvlcak.dependency_updater_mcp.tool.GitHubTools;
import org.jetbrains.annotations.NotNull;
import org.kohsuke.github.GHContent;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static dev.mvlcak.dependency_updater_mcp.agent.GradleParser.parseGradleForDeps;
import static dev.mvlcak.dependency_updater_mcp.agent.PomParser.parsePomAndGetDependencies;

/**
 * AGENT — Dependency upgrade / CVE remediation.
 *
 * Goal: the repo has no known-vulnerable dependencies AND still builds green.
 *
 * Marked below:
 *   [CODE] = no LLM. Ordinary Java. Deterministic, testable, free.
 *   [LLM]  = a real model call via context.ai(). The LLM may drive tools here.
 *
 * The point for the audience: only 3 of 8 actions touch a model.
 * The planner (GOAP) chooses the path between them without any LLM at all.
 */
@Agent(
        name = "dependency-upgrade",
        description = "Finds vulnerable dependencies, upgrades them, repairs the build, and raises a PR"
)
public class DependencyUpgradeAgent {

    private static final Logger log = LoggerFactory.getLogger(DependencyUpgradeAgent.class);

    /** How many upgrades we will attempt before handing back to a human. */
    private static final int MAX_UPGRADE_ATTEMPTS = 5;

    /** Handed to the LLM as a tool object — the model decides when to call it. */
    private final GitHubTools gitHubTools;

    /** The same client, for [CODE] actions that call GitHub directly. No LLM involved. */
    private final GitHub gitHub;

    /** OSV.dev lookups. Deterministic — the model never gets a say in what counts as a CVE. */
    private final OsvClient osvClient;

    public DependencyUpgradeAgent(GitHubTools gitHubTools, GitHub gitHub, OsvClient osvClient) {
        this.gitHubTools = gitHubTools;
        this.gitHub = gitHub;
        this.osvClient = osvClient;
    }

    // Inject your own Spring beans here: build runner, VCS client, scanner client,
    // and a repoTools bean whose @Tool methods let an LLM read/write/grep files.
    // private final BuildService build;
    // private final RepoTools repoTools;
    // private final ScannerClient scanner;

    // ── ACTIONS ────────────────────────────────────────────────────────────────

    /**
     * [CODE] Entry point. Turn the user's request ("check payments-service")
     * into a concrete repo reference: clone or open a local working copy,
     * resolve the branch, and confirm the build tool is Maven/Gradle.
     * Fail fast here if the repo is dirty — never start from uncommitted changes.
     */
    @Action
    GHRepository openRepo(UserInput input, Ai ai) {
        return ai.withDefaultLlm()
                .withToolObject(gitHubTools)
                .creating(GHRepository.class)
                .fromPrompt("""
                        Your task is to search in github with tool for repository of related owner.
                        Pass filled out RepoRef
                      
                        Here is input from user
                        %s
                        """
                        .formatted(input.getContent()));
    }

    /**
     * [CODE] Parse pom.xml / build.gradle into a typed Manifest:
     * every direct and transitive dependency with its resolved version.
     * Pure parsing — no model needed, and the type safety is the whole point.
     */
    @Action
    Manifest readManifest(GHRepository repo) {
        List<GHContent> root = null;
        try {
            root = repo.getDirectoryContent("/");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        Set<String> names = root.stream().map(GHContent::getName).collect(Collectors.toSet());
        if (names.contains("pom.xml")) {
            return new Manifest("pom.xml", parsePomAndGetDependencies(repo));
        }
        if (names.contains("build.gradle")) {
            return parseGradleAndGetDependencies(repo,"build.gradle");
        }
        if (names.contains("build.gradle.kts")){
            return parseGradleAndGetDependencies(repo,"build.gradle.kts");
        }
        throw new RuntimeException("unknown build tool");
    }

    private Manifest parseGradleAndGetDependencies(GHRepository repo, String fileName) {
        List<Dependency> dependencies;
        String content;
        content = getContentOfFileFromRepo(repo, fileName);

        dependencies = parseGradleForDeps(content);

        return new Manifest(fileName, dependencies);
    }

    @NotNull
    static String getContentOfFileFromRepo(GHRepository repo, String fileName) {
        String content;
        try {
            content =  new BufferedReader(new InputStreamReader(repo.getFileContent(fileName).read()))
                    .lines().parallel().collect(Collectors.joining("\n"));

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return content;
    }

    /**
     * [CODE] Send the manifest to OSV.dev (or your Nexus/Snyk/Artifactory scanner)
     * and return the CVEs that actually apply, with severity and the fixed version.
     * Returns an empty report if the repo is already clean — which satisfies the
     * goal immediately and lets the planner skip everything below. Good thing to
     * demo: run it on a clean repo and show the short plan.
     */
    @Action
    VulnerabilityReport scan(Manifest manifest) {
        return new VulnerabilityReport(osvClient.findVulnerabilities(manifest.dependencies()));
    }

    /**
     * [LLM] Decide WHICH upgrade to attempt first when several CVEs are open.
     * Weigh severity against blast radius (a test-scoped lib is safer than a
     * framework core), and pick the smallest version bump that clears the CVE.
     * Returns one ProposedUpgrade — deliberately one at a time, so a failure
     * is attributable. Use a low temperature and a cheap model.
     */
    @Action(canRerun = true, pre = "upgradesRemain")
    ProposedUpgrade chooseUpgrade(VulnerabilityReport report, Manifest manifest, OperationContext ctx) {
        List<UpgradeShortlist.Candidate> candidates = UpgradeShortlist.from(report, attemptedCoordinates(ctx));
        if (candidates.isEmpty()) {
            // The upgradesRemain precondition should have stopped us being planned at all.
            throw new IllegalStateException("chooseUpgrade planned with nothing left to upgrade");
        }

        UpgradeChoice choice = ctx.ai().withDefaultLlm()
                .creating(UpgradeChoice.class)
                .fromPrompt("""
                        You are choosing ONE dependency upgrade to attempt next, in a repo built with %s.

                        Weigh severity against blast radius. A test-scoped library is safer to move than a
                        framework core. Prefer the SMALLEST bump that clears the most severe CVEs — a larger
                        jump closes more advisories but is far more likely to break the build.

                        Candidates, most severe first:
                        %s

                        Answer with:
                          coordinate    — exactly one of the coordinates listed above
                          targetVersion — exactly one of that candidate's listed fix versions
                          rationale     — one or two sentences on why this one, and why that version
                        """
                        .formatted(manifest.path(), describe(candidates)));

        return toProposedUpgrade(choice, candidates);
    }

    /** Renders the shortlist as compact text. The model sees only vetted facts. */
    private String describe(List<UpgradeShortlist.Candidate> candidates) {
        StringBuilder text = new StringBuilder();
        for (UpgradeShortlist.Candidate candidate : candidates) {
            text.append("- %s%n    current version: %s (scope: %s)%n    worst severity: %s across %d CVEs: %s%n    fix versions: %s%n"
                    .formatted(
                            candidate.coordinate(),
                            candidate.dependency().version(),
                            candidate.dependency().scope(),
                            candidate.worstSeverity(),
                            candidate.cveIds().size(),
                            String.join(", ", candidate.cveIds()),
                            String.join(", ", candidate.fixVersions())));
        }
        return text.toString();
    }

    /**
     * Maps the model's choice back onto real data, rejecting anything it invented.
     * An unrecognised coordinate or version falls back to the safest available option
     * rather than failing the run — the planner can still make progress.
     */
    private ProposedUpgrade toProposedUpgrade(UpgradeChoice choice, List<UpgradeShortlist.Candidate> candidates) {
        UpgradeShortlist.Candidate chosen = candidates.stream()
                .filter(candidate -> candidate.coordinate().equalsIgnoreCase(choice.coordinate()))
                .findFirst()
                .orElseGet(() -> {
                    log.warn("LLM chose unknown coordinate '{}' — falling back to the most severe candidate",
                            choice.coordinate());
                    return candidates.getFirst();
                });

        String targetVersion = chosen.fixVersions().contains(choice.targetVersion())
                ? choice.targetVersion()
                : chosen.smallestFix();
        if (!targetVersion.equals(choice.targetVersion())) {
            log.warn("LLM chose version '{}' which is not a known fix for {} — falling back to {}",
                    choice.targetVersion(), chosen.coordinate(), targetVersion);
        }

        return new ProposedUpgrade(
                chosen.dependency(),
                targetVersion,
                chosen.cveIds().getFirst(),
                choice.rationale());
    }

    /** "group:artifact" for every upgrade proposed so far in this run, from the blackboard. */
    private Set<String> attemptedCoordinates(OperationContext ctx) {
        return ctx.objectsOfType(ProposedUpgrade.class).stream()
                .map(upgrade -> upgrade.current().group() + ":" + upgrade.current().artifact())
                .collect(Collectors.toSet());
    }

    /**
     * [LLM + WEB TOOLS] Only planned when isMajorBump is true.
     * Search the web for the library's migration guide and release notes between
     * the current and target version, and extract the breaking changes that are
     * likely to affect this codebase. Attach CoreToolGroups.WEB so the model can
     * fetch pages itself. Feeds the repair step below with real context instead
     * of letting it guess from the stack trace.
     */
    @Action(pre = "isMajorBump")
    MigrationNotes researchMigration(ProposedUpgrade upgrade, OperationContext ctx) {
        return null;
    }

    /**
     * [CODE] Edit the version in the manifest and run the build (`mvn -q verify`).
     * Capture exit code, failing test names, and the compiler/test output.
     * This is the oracle — the whole demo rests on this being real and honest.
     * Deterministic on purpose: your code triggers this tool, not the model.
     */
    @Action(canRerun = true)
    BuildResult applyAndBuild(ProposedUpgrade upgrade) {
        return null;
    }

    /**
     * [LLM + TOOL OBJECTS] Only planned when the build is red.
     * Give the model the failure output, the migration notes if present, and a
     * repoTools object it can call to read, grep and write source files. It should
     * fix the CALLING code to match the new API — never revert the version bump.
     * After it returns, the planner will route back to applyAndBuild, and around
     * the loop again. THIS is the moment to point at on stage.
     */
    @Action(canRerun = true, pre = "buildFailed")
    Patch repair(BuildResult result, OperationContext ctx) {
        return null;
    }

    /**
     * [CODE + LLM] Goal. Only reachable on a green build.
     * Commit on a branch, push, and open a draft PR. The LLM writes the title and
     * body: which CVE this closes, what changed and why, what a reviewer should
     * look at hardest. Everything else is a plain API call.
     *
     * Keep it a DRAFT and gate the push behind confirmation — in the presentation
     * that reads as good engineering rather than a limitation.
     */
    @Action(pre = {"buildGreen", "allUpgradesAddressed"})
    @AchievesGoal(description = "Vulnerable dependencies upgraded, build green, PR open for review")
    PullRequest raisePullRequest(BuildResult result, ProposedUpgrade upgrade, OperationContext ctx) {
        return null;
    }

    // ── CONDITIONS ─────────────────────────────────────────────────────────────
    // These are what the planner reasons over. Adding a condition changes the
    // available paths without you editing a single existing action.

    /** True when the target version crosses a major boundary — triggers research. */
    @Condition(name = "isMajorBump")
    boolean isMajorBump(ProposedUpgrade upgrade) {
        return false;
    }

    /** True when the last build was red — triggers repair. */
    @Condition(name = "buildFailed")
    boolean buildFailed(BuildResult result) {
        return false;
    }

    /** True when the last build passed — unlocks the goal. */
    @Condition(name = "buildGreen")
    boolean buildGreen(BuildResult result) {
        return false;
    }

    /**
     * True while at least one vulnerable dependency has not yet been proposed.
     *
     * This is what makes the loop turn. chooseUpgrade is gated on it and marked
     * canRerun, so after each green build the planner comes back here, finds work
     * left, and plans another pass. When it finally goes false, the only action
     * still available is the goal.
     *
     * Note it reads the blackboard rather than any single action's output: every
     * ProposedUpgrade ever produced in this run is still there, so "what have we
     * already tried" is simply a query, not state we have to thread through types.
     */
    @Condition(name = "upgradesRemain")
    boolean upgradesRemain(OperationContext ctx) {
        VulnerabilityReport report = ctx.last(VulnerabilityReport.class);
        if (report == null) {
            return false;
        }
        if (retryBudgetExhausted(ctx)) {
            log.warn("Upgrade budget of {} exhausted — stopping while work remains", MAX_UPGRADE_ATTEMPTS);
            return false;
        }
        return !UpgradeShortlist.from(report, attemptedCoordinates(ctx)).isEmpty();
    }

    /** The inverse — the goal is only reachable once there is nothing left to attempt. */
    @Condition(name = "allUpgradesAddressed")
    boolean allUpgradesAddressed(OperationContext ctx) {
        return !upgradesRemain(ctx);
    }

    /**
     * Guard rail. Without this the agent will happily loop forever in front of your CTO.
     * The count is just how many ProposedUpgrades are sitting on the blackboard.
     */
    @Condition(name = "retryBudgetExhausted")
    boolean retryBudgetExhausted(OperationContext ctx) {
        return ctx.count(ProposedUpgrade.class) >= MAX_UPGRADE_ATTEMPTS;
    }
}

// ── DOMAIN MODEL ───────────────────────────────────────────────────────────────
// Plain records. These types ARE the plan: the planner connects actions by
// matching what each one consumes and produces. Rename one and the compiler
// tells you what broke — which is the argument for doing this on the JVM.
