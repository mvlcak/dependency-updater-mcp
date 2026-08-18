package dev.mvlcak.dependency_updater_mcp.agent;


import com.embabel.agent.api.annotation.*;
import com.embabel.agent.api.common.Ai;
import com.embabel.agent.api.common.OperationContext;
import com.embabel.agent.core.CoreToolGroups;
import com.embabel.agent.domain.io.UserInput;
import dev.mvlcak.dependency_updater_mcp.domain.*;
import dev.mvlcak.dependency_updater_mcp.osv.OsvClient;
import dev.mvlcak.dependency_updater_mcp.tool.GitHubTools;
import jakarta.validation.constraints.NotNull;
import org.kohsuke.github.GHPullRequest;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 *  Dependency upgrade / CVE remediation.
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

    private final GitHub gitHub;

    /** OSV.dev lookups. Deterministic — the model never gets a say in what counts as a CVE. */
    private final OsvClient osvClient;

    private final String githubToken;

    /**
     * Off by default.
     */
    private final boolean pushEnabled;

    public DependencyUpgradeAgent(GitHubTools gitHubTools,
                                  GitHub gitHub,
                                  OsvClient osvClient,
                                  @Value("${github.token:}") String githubToken,
                                  @Value("${dependency-upgrader.push-enabled:false}") boolean pushEnabled) {
        this.gitHubTools = gitHubTools;
        this.gitHub = gitHub;
        this.osvClient = osvClient;
        this.githubToken = githubToken;
        this.pushEnabled = pushEnabled;
    }

    @Action
    RepoCoordinates findRepo(UserInput input, Ai ai) {
        return ai.withDefaultLlm()
                .withToolObject(gitHubTools)
                .creating(RepoCoordinates.class)
                .fromPrompt("""
                        Work out which GitHub repository the user means, and answer with its
                        owner and repository name — nothing else, no URL, no "owner/name" in
                        one field.

                        Use the GitHub search tool if the request is ambiguous or gives only a
                        partial name. If the user states the owner and repository outright, just
                        return them.

                        The user asked:
                        %s
                        """
                        .formatted(input.getContent()));
    }

    @Action
    GHRepository openRepo(RepoCoordinates coordinates) {
        try {
            return gitHub.getRepository(coordinates.fullName());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Cannot open %s. It may not exist, or the configured github.token may not see it."
                            .formatted(coordinates.fullName()), e);
        }
    }

    @Action
    BuildWorkspace checkout(GHRepository repo) {
        return BuildWorkspace.checkout(repo, githubToken);
    }

    @Action
    Manifest readManifest(BuildWorkspace workspace) {
        return new Manifest(workspace.buildFile(), workspace.resolveDependencies());
    }

    @Action(post = "upgradesRemain")
    VulnerabilityReport scan(Manifest manifest) {
        return new VulnerabilityReport(osvClient.findVulnerabilities(manifest.dependencies()));
    }

    @Action(canRerun = true, pre = "upgradesRemain", post = {"allUpgradesAddressed", "isMajorBump"})
    ProposedUpgrade chooseUpgrade(VulnerabilityReport report, Manifest manifest, OperationContext ctx) {
        List<UpgradeShortlist.Candidate> candidates = UpgradeShortlist.from(report, attemptedUpgrades(ctx));
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

    @Action(canRerun = true, post = {"buildGreen", "buildFailed"})
    BuildResult applyAndBuild(ProposedUpgrade upgrade, BuildWorkspace workspace) {
        workspace.applyVersion(upgrade);
        BuildResult result = workspace.build();

        if (result.passed()) {
            // Green is the only thing that earns a commit. This is what the branch is
            // made of — without it raisePullRequest pushes nothing but the baseline.
            workspace.checkpoint("""
                    Upgrade %s:%s from %s to %s

                    Closes %s.
                    %s"""
                    .formatted(upgrade.current().group(), upgrade.current().artifact(),
                            upgrade.current().version(), upgrade.targetVersion(),
                            upgrade.cveId(), upgrade.rationale()));
        }
        // A red tree is deliberately left as it is: repair needs to see the breakage,
        // and rewinding is the job of whichever action decides to give up on it.
        return result;
    }

    /**
     * Give up on an upgrade that will not build, and hand the planner a green tree again.
     *
     * Nothing calls this. It gets *planned*: after a red build `buildFailed` is true and
     * this is the only other action that can produce `buildGreen`, which the goal needs.
     */
    @Action(canRerun = true, pre = "buildFailed", post = "buildGreen")
    BuildResult abandonFailedUpgrade(ProposedUpgrade upgrade,
                                     BuildWorkspace workspace,
                                     OperationContext ctx) {
        log.warn("Giving up on {}:{} -> {} — reverting to {}",
                upgrade.current().group(), upgrade.current().artifact(),
                upgrade.targetVersion(), workspace.lastGreenSha());

        BuildResult red = ctx.last(BuildResult.class);
        workspace.revertToLastGreen();

        // The evidence that the reverted tree is green is a build we already ran: the one
        // that earned the last checkpoint, or the baseline taken before anything was edited.
        // Not a fabricated success, and not another 15-minute build on stage.
        BuildResult evidence = ctx.objectsOfType(BuildResult.class).stream()
                .filter(BuildResult::passed)
                .reduce((earlier, later) -> later)
                .orElse(workspace.baseline());

        // Record the abandonment on the branch. The revert leaves the tree byte-identical to
        // the base, so without a commit here the branch holds nothing and raisePullRequest —
        // the step the planner replans to next — has nothing to open and fails the run. An
        // empty commit is the cheapest honest way to say "attempted, rejected, here is why".
        workspace.checkpoint("""
            Abandon %s:%s %s -> %s
            
            This upgrade would close %s, but the build did not survive it:
            exit %d, failing tests: %s.
            
            The working tree was reverted, so %s is still open and needs a human."""
                .formatted(upgrade.current().group(), upgrade.current().artifact(),
                        upgrade.current().version(), upgrade.targetVersion(),
                        upgrade.cveId(),
                        red == null ? -1 : red.exitCode(),
                        red == null || red.failingTests().isEmpty()
                                ? "none reported (the build failed before the tests ran)"
                                : String.join(", ", red.failingTests()),
                        upgrade.cveId()));

        return new BuildResult(true, 0, List.of(),
                "Abandoned %s:%s -> %s and reverted to %s. That commit built green:%n%s"
                        .formatted(upgrade.current().group(), upgrade.current().artifact(),
                                upgrade.targetVersion(), workspace.lastGreenSha(), evidence.output()));
    }

    @Action(pre = {"buildGreen", "allUpgradesAddressed"})
    @AchievesGoal(description = "Updates dependencies of either Maven or Gradle project in Github repository for Github user to mitigate CVEs",
            export = @Export(
                    name = "upgrade_dependencies",
                    remote = true,
                    startingInputTypes = {RepoCoordinates.class}))
    PullRequest raisePullRequest(GHRepository repo,
                                 BuildWorkspace workspace,
                                 BuildResult result,
                                 OperationContext ctx) {
        // Every upgrade attempted in this run, not just the last one bound to a parameter.
        List<ProposedUpgrade> upgrades = ctx.objectsOfType(ProposedUpgrade.class);
        if (upgrades.isEmpty()) {
            throw new IllegalStateException("Nothing was upgraded — refusing to open an empty pull request");
        }
        // A proposal on the blackboard is not the same as a commit on the branch: an
        // upgrade that never went green was never committed, and there may be nothing
        // to review even though the run looks like it did some work.
        if (workspace.commitsAhead() == 0) {
            throw new IllegalStateException(
                    "%s has no commits beyond %s — %d upgrade(s) were proposed but none were committed"
                            .formatted(workspace.branch(), workspace.baseBranch(), upgrades.size()));
        }

        PullRequestText text = ctx.ai().withDefaultLlm()
                .creating(PullRequestText.class)
                .fromPrompt("""
                        Write the title and body of a pull request for an automated dependency
                        upgrade, addressed to the engineer who has to review it.

                        Repository:  %s
                        Build:       %s, green (exit %d)
                        Upgrades applied, in the order they were attempted:
                        %s

                        The title is one line, imperative, under 70 characters.

                        The body should tell a reviewer, in short prose:
                          - what was upgraded and why it needed to move
                          - what is genuinely worth looking at hardest, and be specific about it:
                            a major version bump deserves more scrutiny than a patch
                          - that the build passed, and that a green build is evidence rather than proof

                        Use ONLY the facts above. Do not invent advisory ids, versions, file names
                        or test names, and do not restate the version table — it is appended below
                        your text automatically. No greeting, no sign-off, no emoji.
                        """
                        .formatted(repo.getFullName(), workspace.buildFile(),
                                result.exitCode(), describeUpgrades(upgrades)));

        String body = text.body() + upgradeTable(upgrades);

        if (!pushEnabled) {
            log.info("""
                    DRY RUN — set dependency-upgrader.push-enabled=true to publish.
                    Would push {} onto {} of {} and open a draft PR:
                    {}
                    {}""", workspace.branch(), workspace.baseBranch(), repo.getFullName(), text.title(), body);
            return new PullRequest("(dry run — nothing was pushed)", text.title(), body);
        }

        workspace.push(githubToken);
        try {
            GHPullRequest created = repo.createPullRequest(
                    text.title(), workspace.branch(), workspace.baseBranch(), body, true, true);
            log.info("Opened draft PR {}", created.getHtmlUrl());
            return new PullRequest(created.getHtmlUrl().toString(), text.title(), body);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Pushed %s but could not open the pull request against %s"
                            .formatted(workspace.branch(), repo.getFullName()), e);
        }
    }

    /** True when the target version crosses a major boundary — triggers research. */
    @Condition(name = "isMajorBump")
    boolean isMajorBump(ProposedUpgrade upgrade) {
        return crossesMajorBoundary(upgrade.current().version(), upgrade.targetVersion());
    }

    /** True when the last build was red — triggers repair. */
    @Condition(name = "buildFailed")
    boolean buildFailed(BuildResult result) {
        if (result.exitCode() != 0){
            return true;
        }
        if (!result.passed()){
            return true;
        }
        return !result.failingTests().isEmpty();
    }

    /** True when the last build passed — unlocks the goal. */
    @Condition(name = "buildGreen")
    boolean buildGreen(BuildResult result) {
        return result.exitCode() == 0 && result.failingTests().isEmpty() && result.passed();
    }

    /**
     * True while at least one vulnerable dependency has not yet been proposed.
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
        return !UpgradeShortlist.from(report, attemptedUpgrades(ctx)).isEmpty();
    }

    /**
     * The inverse — the goal is only reachable once there is nothing left to attempt.
     *
     * The report check is not redundant. Without it this is true before anything has
     * been scanned, so the goal looks half-satisfied at t=0 and the planner is happy
     * to reach it without ever looking for a vulnerability.
     */
    @Condition(name = "allUpgradesAddressed")
    boolean allUpgradesAddressed(OperationContext ctx) {
        return ctx.last(VulnerabilityReport.class) != null && !upgradesRemain(ctx);
    }

    /**
     * Guard rail. Without this the agent will happily loop forever in front of your CTO.
     * The count is just how many ProposedUpgrades are sitting on the blackboard.
     */
    @Condition(name = "retryBudgetExhausted")
    boolean retryBudgetExhausted(OperationContext ctx) {
        return ctx.count(ProposedUpgrade.class) >= MAX_UPGRADE_ATTEMPTS;
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
     * Semver, with the two caveats that actually matter in a Maven repo.
     *
     * Below 1.0 there is no API stability promise at all, so 0.9 -> 0.10 counts as a
     * major bump. And anything we cannot parse — a calendar version, a vendor suffix,
     * a range — counts as major too: researching a patch bump costs one web search,
     * missing a breaking change costs a red build that repair has no context for.
     */
    static boolean crossesMajorBoundary(String currentVersion, String targetVersion) {
        Integer currentMajor = segment(currentVersion, 0);
        Integer targetMajor = segment(targetVersion, 0);

        if (currentMajor == null || targetMajor == null) {
            log.warn("Cannot compare '{}' to '{}' — assuming a major bump and researching it",
                    currentVersion, targetVersion);
            return true;
        }
        if (!currentMajor.equals(targetMajor)) {
            return true;
        }
        if (currentMajor == 0) {
            Integer currentMinor = segment(currentVersion, 1);
            Integer targetMinor = segment(targetVersion, 1);
            return currentMinor == null || !currentMinor.equals(targetMinor);
        }
        return false;
    }

    /** The vetted facts the model is allowed to write about. */
    private String describeUpgrades(List<ProposedUpgrade> upgrades) {
        StringBuilder text = new StringBuilder();
        for (ProposedUpgrade upgrade : upgrades) {
            text.append("- %s:%s %s -> %s (closes %s)%n    rationale: %s%n".formatted(
                    upgrade.current().group(), upgrade.current().artifact(),
                    upgrade.current().version(), upgrade.targetVersion(),
                    upgrade.cveId(), upgrade.rationale()));
        }
        return text.toString();
    }

    /** Appended after the model's prose, so the numbers a reviewer trusts come from code. */
    private String upgradeTable(List<ProposedUpgrade> upgrades) {
        StringBuilder table = new StringBuilder("%n%n---%n%n| Dependency | From | To | Advisory |%n|---|---|---|---|%n"
                .formatted());
        for (ProposedUpgrade upgrade : upgrades) {
            table.append("| `%s:%s` | %s | %s | %s |%n".formatted(
                    upgrade.current().group(), upgrade.current().artifact(),
                    upgrade.current().version(), upgrade.targetVersion(), upgrade.cveId()));
        }
        return table.append("%nOpened as a draft by the dependency-upgrade agent.".formatted()).toString();
    }

    /**
     * The numeric value of one version segment, or null if it isn't a number.
     * Splits on the separators Maven versions actually use, so "3.0.0-M1" yields 3 and 0,
     * and "5.3.39.RELEASE" yields 5 and 3.
     */
    private static Integer segment(String version, int index) {
        if (version == null || version.isBlank()) {
            return null;
        }
        String[] parts = version.trim().split("[.\\-_+]");
        if (index >= parts.length) {
            return null;
        }
        try {
            return Integer.valueOf(parts[index]);
        } catch (NumberFormatException _) {
            return null;
        }
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

    /**
     * "group:artifact:targetVersion" for every upgrade proposed so far in this run.
     *
     * Keyed by version, not by coordinate. A red build rules out the version that was
     * applied, not the dependency: the other fix versions have never been tried. Retiring
     * the whole coordinate on the first failure means a repo with a single vulnerable
     * dependency has nowhere to replan to after abandonFailedUpgrade — upgradesRemain goes
     * false, the branch holds no commits, and raisePullRequest has nothing to open.
     *
     * Termination still comes from retryBudgetExhausted plus an exhausted shortlist, since
     * every attempt puts one more ProposedUpgrade on the blackboard.
     */
    private Set<String> attemptedUpgrades(OperationContext ctx) {
        return ctx.objectsOfType(ProposedUpgrade.class).stream()
                .map(upgrade -> upgrade.current().group() + ":" + upgrade.current().artifact()
                        + ":" + upgrade.targetVersion())
                .collect(Collectors.toSet());
    }
}

