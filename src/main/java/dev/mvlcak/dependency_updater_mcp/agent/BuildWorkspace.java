package dev.mvlcak.dependency_updater_mcp.agent;

import dev.mvlcak.dependency_updater_mcp.domain.BuildResult;
import dev.mvlcak.dependency_updater_mcp.domain.Dependency;
import dev.mvlcak.dependency_updater_mcp.domain.ProposedUpgrade;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.kohsuke.github.GHRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The local working copy. The only thing in this agent that touches the filesystem.
 *
 * Its whole reason to exist is one invariant: a red build means THIS upgrade broke
 * something. Everything here serves that — the baseline build before any edit, the
 * per-repo JDK, the commit on green, the reset on abandon. Without them a red build
 * could mean the repo never compiled on this machine, and repair would burn model
 * calls fixing code that was never broken.
 *
 * The tree is always at the last green commit when a new upgrade is chosen.
 * Repairs made during an in-flight attempt are NOT reverted — they belong to that
 * attempt and get committed with it.
 *
 * Note it holds a Path into a temp directory: fine on an in-memory blackboard, but
 * it will not survive a persisted AgentProcess being resumed in another JVM.
 */
public final class BuildWorkspace implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(BuildWorkspace.class);

    /** A build that has not finished by now is hung. Fail the attempt, not the agent. */
    private static final Duration BUILD_TIMEOUT = Duration.ofMinutes(15);

    /** Build logs go into an LLM prompt. Keep the tail — the failure is always at the end. */
    private static final int MAX_OUTPUT_CHARS = 20_000;

    /** `<version>` is absent when a parent BOM manages it; we insert one after this. */
    private static final Pattern DEPENDENCY_BLOCK =
            Pattern.compile("<dependency>(.*?)</dependency>", Pattern.DOTALL);
    private static final Pattern VERSION_ELEMENT =
            Pattern.compile("<version>\\s*([^<]*?)\\s*</version>");
    private static final Pattern PROPERTY_PLACEHOLDER = Pattern.compile("^\\$\\{([^}]+)}$");

    /**
     * `[ERROR] com.example.FooTest.shouldWork -- Time elapsed: 0.007 s <<< ERROR!`
     * Surefire 3.x's per-test line. Preferred: it is the only one carrying the package.
     */
    private static final Pattern SUREFIRE_DETAIL = Pattern.compile(
            "(?m)^\\[ERROR]\\s+([\\w$.]+\\.[\\w$]+)\\s+--\\s+Time elapsed:.*<<<\\s+(?:FAILURE|ERROR)!");
    /**
     * The trailing summary block, in both shapes surefire emits:
     * `[ERROR]   FooTest.shouldWork:42 expected:<1>` and `[ERROR]   FooTest.boom » IllegalState`.
     * Two leading spaces are what separates these from `[ERROR] Failed to execute goal ...`.
     */
    private static final Pattern SUREFIRE_SUMMARY =
            Pattern.compile("(?m)^\\[ERROR]\\s{2,}([\\w$.]+\\.[\\w$]+)(?::\\d+|\\s+»)");
    /** `FooTest > shouldWork FAILED` — Gradle's test reporter. */
    private static final Pattern GRADLE_FAILURE =
            Pattern.compile("(?m)^(\\S+)\\s+>\\s+(\\S+)\\s+FAILED\\s*$");
    public static final String ARTIFACT_ID = "</artifactId>";

    enum BuildTool {MAVEN, GRADLE}

    private final Path root;
    private final String buildFile;
    private final BuildTool tool;
    private final Path javaHome;
    private final BuildResult baseline;

    /** The repo's default branch — what the pull request will target. */
    private final String baseBranch;

    /** Created before the first edit, so every checkpoint lands on it. */
    private final String branch;

    /** Moves forward on every green build; where an abandoned upgrade rewinds to. */
    private String lastGreenSha;

    private BuildWorkspace(Path root, String buildFile, BuildTool tool, Path javaHome,
                           BuildResult baseline, String baseBranch, String branch) {
        this.root = root;
        this.buildFile = buildFile;
        this.tool = tool;
        this.javaHome = javaHome;
        this.baseline = baseline;
        this.baseBranch = baseBranch;
        this.branch = branch;
    }

    // ── SETUP ──────────────────────────────────────────────────────────────────

    /**
     * Clone, work out how to build it, and prove it builds BEFORE anything is changed.
     *
     * @throws IllegalStateException if the pristine tree does not build. That is not an
     *                               agent failure to recover from — there is no honest
     *                               signal to be had from this repo on this machine.
     */
    static BuildWorkspace checkout(GHRepository repo, String token) {
        Path root = createTempDirectory();
        clone(repo, token, root);

        String buildFile = detectBuildFile(root);
        BuildTool tool = buildFile.equals("pom.xml") ? BuildTool.MAVEN : BuildTool.GRADLE;
        Path javaHome = resolveJavaHome(requiredJavaMajor(root, buildFile, tool));

        String baseBranch = repo.getDefaultBranch();
        BuildWorkspace probe = new BuildWorkspace(root, buildFile, tool, javaHome, null, baseBranch, null);
        log.info("Baseline build of {} ({}) — proving the tree is green before touching it",
                repo.getFullName(), buildFile);
        BuildResult baseline = probe.build();
        if (!baseline.passed()) {
            probe.close();
            throw new IllegalStateException(
                    "%s does not build before any upgrade is applied (exit %d, %d failing tests). "
                            .formatted(repo.getFullName(), baseline.exitCode(), baseline.failingTests().size())
                            + "Every later red build would be unattributable, so stopping here. "
                            + "Check the JDK: this repo was built with "
                            + (javaHome == null ? "the agent's own JVM" : javaHome));
        }

        // The branch is cut here, before anything is edited, so every later checkpoint
        // lands on it and the name is decided exactly once.
        String branch = "deps/cve-remediation-"
                + DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC).format(Instant.now());
        BuildWorkspace ready = new BuildWorkspace(root, buildFile, tool, javaHome, baseline, baseBranch, branch);
        ready.git("checkout", "-b", branch);
        ready.lastGreenSha = ready.head();
        log.info("Working on {} (base {}) at {}", branch, baseBranch, ready.lastGreenSha);
        return ready;
    }

    private static Path createTempDirectory() {
        try {
            return Files.createTempDirectory("dependency-upgrade-");
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create a working directory", e);
        }
    }

    /**
     * Shallow clone of the default branch.
     *
     * The token goes in via GIT_ASKPASS rather than the URL: a token embedded in a
     * remote URL turns up in `ps`, in git's own error messages, and in .git/config.
     */
    private static void clone(GHRepository repo, String token, Path root) {
        List<String> command = new ArrayList<>(List.of(
                "git", "clone", "--depth", "1",
                "--branch", repo.getDefaultBranch(),
                repo.getHttpTransportUrl(), root.toString()));

        ProcessBuilder builder = new ProcessBuilder(command);
        authenticate(builder, token, root.getParent());

        ProcessOutcome outcome = run(builder, Duration.ofMinutes(5));
        if (outcome.exitCode() != 0) {
            throw new IllegalStateException("git clone of %s failed (exit %d):%n%s"
                    .formatted(repo.getFullName(), outcome.exitCode(), outcome.output()));
        }
    }

    /** GIT_TERMINAL_PROMPT=0 matters as much as the token: without it git hangs on a prompt. */
    private static void authenticate(ProcessBuilder builder, String token, Path scratchDirectory) {
        builder.environment().put("GIT_TERMINAL_PROMPT", "0");
        if (token != null && !token.isBlank()) {
            builder.environment().put("GIT_ASKPASS", askpassScript(scratchDirectory).toString());
            builder.environment().put("DEPENDENCY_UPGRADER_TOKEN", token);
        }
    }

    private static Path askpassScript(Path directory) {
        try {
            Path script = Files.createTempFile(directory, "askpass-", ".sh");
            Files.writeString(script, """
                    #!/bin/sh
                    case "$1" in
                      Username*) echo "x-access-token" ;;
                      *)         echo "$DEPENDENCY_UPGRADER_TOKEN" ;;
                    esac
                    """);
            if (!script.toFile().setExecutable(true, true)) {
                throw new IllegalStateException("Cannot make the credential helper executable");
            }
            return script;
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write the credential helper", e);
        }
    }

    private static String detectBuildFile(Path root) {
        for (String candidate : List.of("pom.xml", "build.gradle", "build.gradle.kts")) {
            if (Files.exists(root.resolve(candidate))) {
                return candidate;
            }
        }
        throw new IllegalStateException("No pom.xml or build.gradle in the repository root");
    }

    // ── JDK SELECTION ──────────────────────────────────────────────────────────

    /**
     * The JDK the repo asks for, not the one the agent happens to be running on.
     *
     * Building an old repo on a new JDK fails in ways that look exactly like a broken
     * upgrade — Lombok, ByteBuddy, and Gradle itself all hard-fail on a class file
     * version they predate. Getting this wrong makes the oracle lie.
     */
    private static Integer requiredJavaMajor(Path root, String buildFile, BuildTool tool) {
        String content = read(root.resolve(buildFile));
        Integer major = tool == BuildTool.MAVEN ? mavenJavaMajor(content) : gradleJavaMajor(content);
        if (major == null) {
            log.warn("Cannot tell which JDK {} targets — using the agent's own JVM", buildFile);
        }
        return major;
    }

    private static Integer mavenJavaMajor(String pomContent) {
        Model model;
        try {
            model = new MavenXpp3Reader().read(new StringReader(pomContent));
        } catch (IOException | XmlPullParserException e) {
            return null;
        }
        for (String key : List.of("maven.compiler.release", "java.version",
                "maven.compiler.target", "maven.compiler.source")) {
            Integer major = majorOf(model.getProperties().getProperty(key));
            if (major != null) {
                return major;
            }
        }
        return null;
    }

    private static Integer gradleJavaMajor(String buildContent) {
        for (Pattern pattern : List.of(
                Pattern.compile("languageVersion\\s*=?\\s*JavaLanguageVersion\\.of\\(\\s*(\\d+)\\s*\\)"),
                Pattern.compile("(?:source|target)Compatibility\\s*=?\\s*(?:JavaVersion\\.VERSION_)?['\"]?([\\d_.]+)['\"]?"))) {
            Matcher matcher = pattern.matcher(buildContent);
            if (matcher.find()) {
                Integer major = majorOf(matcher.group(1).replace('_', '.'));
                if (major != null) {
                    return major;
                }
            }
        }
        return null;
    }

    /** "1.8" -> 8, "17" -> 17, "21.0.5" -> 21. */
    private static Integer majorOf(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String[] parts = raw.trim().split("\\.");
        try {
            int first = Integer.parseInt(parts[0]);
            return first == 1 && parts.length > 1 ? Integer.parseInt(parts[1]) : first;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Looks through SDKMAN, then the macOS JVM directory. Null means "inherit ours". */
    private static Path resolveJavaHome(Integer major) {
        if (major == null) {
            return null;
        }
        Path candidates = Path.of(System.getProperty("user.home"), ".sdkman", "candidates", "java");
        if (Files.isDirectory(candidates)) {
            try (var installed = Files.list(candidates)) {
                Path match = installed
                        .filter(path -> path.getFileName().toString().startsWith(major + "."))
                        .filter(path -> Files.exists(path.resolve("bin/javac")))
                        .min(Comparator.comparing(path -> path.getFileName().toString()))
                        .orElse(null);
                if (match != null) {
                    log.info("Building with JDK {} from {}", major, match);
                    return match;
                }
            } catch (IOException e) {
                log.warn("Cannot list SDKMAN installs", e);
            }
        }
        log.warn("Repo targets JDK {} but no matching install was found — using the agent's own JVM. "
                + "Install one with `sdk install java {}.0.0-tem` if the build fails oddly.", major, major);
        return null;
    }

    // ── DEPENDENCY RESOLUTION ──────────────────────────────────────────────────

    /**
     * Ask the build tool what the dependencies actually are.
     *
     * Reading versions out of the build file is not good enough: under a parent POM
     * or a BOM most declarations carry no version at all, so a static parse of a
     * Spring Boot project yields almost nothing to scan and the run dies with an
     * empty vulnerability report. Maven has already resolved all of this — including
     * the transitive graph, which is where most advisories actually live.
     *
     * Falls back to the static parse if resolution fails, on the grounds that a
     * partial dependency list still beats no run at all.
     */
    List<Dependency> resolveDependencies() {
        Path listing;
        try {
            listing = Files.createTempFile("dependency-list-", ".txt");
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create a dependency listing file", e);
        }

        try {
            List<String> command = tool == BuildTool.MAVEN
                    ? List.of(wrapperOr("mvnw", "mvn"), "-B", "-ntp",
                    "dependency:list", "-DoutputFile=" + listing, "-DappendOutput=false")
                    : List.of(wrapperOr("gradlew", "gradle"), "--no-daemon", "--console=plain",
                    "dependencies", "--configuration", "runtimeClasspath");

            ProcessBuilder builder = new ProcessBuilder(command).directory(root.toFile());
            if (javaHome != null) {
                builder.environment().put("JAVA_HOME", javaHome.toString());
            }

            ProcessOutcome outcome = run(builder, Duration.ofMinutes(10));
            if (outcome.exitCode() != 0) {
                log.warn("{} could not resolve dependencies (exit {}) — falling back to parsing {} as written. "
                                + "Versions managed by a parent or BOM will be missing.",
                        tool, outcome.exitCode(), buildFile);
                return staticParse();
            }

            List<Dependency> resolved = tool == BuildTool.MAVEN
                    ? parseMavenList(read(listing))
                    : parseGradleTree(outcome.output());
            if (resolved.isEmpty()) {
                log.warn("Resolution produced no dependencies — falling back to parsing {} as written", buildFile);
                return staticParse();
            }
            log.info("Resolved {} dependencies from {} (including transitives)", resolved.size(), buildFile);
            return resolved;
        } finally {
            try {
                Files.deleteIfExists(listing);
            } catch (IOException e) {
                log.warn("Cannot delete {}", listing, e);
            }
        }
    }

    private List<Dependency> staticParse() {
        String content = read(root.resolve(buildFile));
        return tool == BuildTool.MAVEN
                ? PomParser.parsePomForDeps(content)
                : GradleParser.parseGradleForDeps(content);
    }

    /**
     * `   com.fasterxml.jackson.core:jackson-databind:jar:2.19.0:compile`
     * with an optional classifier before the version and an optional
     * ` -- module x` or ` (optional)` suffix.
     */
    static List<Dependency> parseMavenList(String output) {
        Set<Dependency> dependencies = new LinkedHashSet<>();
        for (String rawLine : output.split("\\R")) {
            String line = rawLine.trim();
            int suffix = line.indexOf(" -- ");
            if (suffix >= 0) {
                line = line.substring(0, suffix).trim();
            }
            suffix = line.indexOf(" (");
            if (suffix >= 0) {
                line = line.substring(0, suffix).trim();
            }

            String[] parts = line.split(":");
            // group:artifact:type:version:scope, or with a classifier in between.
            if (parts.length == 5) {
                dependencies.add(new Dependency(parts[0], parts[1], parts[3], parts[4]));
            } else if (parts.length == 6) {
                dependencies.add(new Dependency(parts[0], parts[1], parts[4], parts[5]));
            }
        }
        return List.copyOf(dependencies);
    }

    /**
     * `+--- com.fasterxml.jackson.core:jackson-databind:2.19.0`, possibly with
     * `2.12.0 -> 2.19.0` when a BOM overrides the requested version — the resolved
     * one is what is on the classpath, so it is the one that matters.
     */
    static List<Dependency> parseGradleTree(String output) {
        Pattern entry = Pattern.compile(
                "(?m)^[|\\\\+\\-\\s]*([A-Za-z0-9_.\\-]+):([A-Za-z0-9_.\\-]+):"
                        + "([A-Za-z0-9_.\\-+]+)(?:\\s+->\\s+([A-Za-z0-9_.\\-+]+))?\\s*(?:\\([^)]*\\))?\\s*$");
        Set<Dependency> dependencies = new LinkedHashSet<>();
        Matcher matcher = entry.matcher(output);
        while (matcher.find()) {
            String version = matcher.group(4) != null ? matcher.group(4) : matcher.group(3);
            dependencies.add(new Dependency(matcher.group(1), matcher.group(2), version, "runtime"));
        }
        return List.copyOf(dependencies);
    }

    // ── THE EDIT ───────────────────────────────────────────────────────────────

    /**
     * Point the manifest at the new version. Text edits, not a model round-trip:
     * rewriting the file through MavenXpp3Writer would reformat every line and bury
     * the one-line change a reviewer needs to see in the PR diff.
     */
    void applyVersion(ProposedUpgrade upgrade) {
        Path manifest = root.resolve(buildFile);
        String before = read(manifest);
        String after = tool == BuildTool.MAVEN
                ? applyMavenVersion(before, upgrade)
                : applyGradleVersion(before, upgrade);
        write(manifest, after);
        log.info("{} -> {} in {}", upgrade.current().group() + ":" + upgrade.current().artifact(),
                upgrade.targetVersion(), buildFile);
    }

    /**
     * Three shapes, all common in the wild: an inline version, a ${property}, or no
     * version at all because a parent BOM manages it. The last one is why this cannot
     * be a single search-and-replace.
     */
    static String applyMavenVersion(String pom, ProposedUpgrade upgrade) {
        String group = upgrade.current().group();
        String artifact = upgrade.current().artifact();

        Matcher blocks = DEPENDENCY_BLOCK.matcher(pom);
        while (blocks.find()) {
            String block = blocks.group(1);
            if (!containsElement(block, "groupId", group) || !containsElement(block, "artifactId", artifact)) {
                continue;
            }

            Matcher version = VERSION_ELEMENT.matcher(block);
            if (!version.find()) {
                // Managed by a parent or an imported BOM: add an explicit override.
                return insertVersionElement(pom, blocks.start(1), block, upgrade.targetVersion());
            }

            Matcher placeholder = PROPERTY_PLACEHOLDER.matcher(version.group(1));
            if (placeholder.matches()) {
                String property = placeholder.group(1);
                String updated = replaceProperty(pom, property, upgrade.targetVersion());
                if (updated != null) {
                    return updated;
                }
                log.warn("Version property '{}' is not declared in this pom — inlining {} instead",
                        property, upgrade.targetVersion());
            }
            int start = blocks.start(1) + version.start(1);
            return pom.substring(0, start) + upgrade.targetVersion() + pom.substring(start + version.group(1).length());
        }

        // Nothing declares it, so it arrived transitively. Maven's supported way to move
        // one of those is a dependencyManagement pin, which wins over whatever version
        // the dependency graph would otherwise resolve to.
        log.info("{}:{} is not declared directly — pinning it to {} in <dependencyManagement>",
                group, artifact, upgrade.targetVersion());
        return pinManagedVersion(pom, upgrade);
    }

    /**
     * Force the version of a dependency nobody declares.
     *
     * Worth knowing when reading the diff: pinning an artifact that a parent BOM also
     * manages deliberately overrides the version set the BOM was tested with. That is
     * the intended effect, and it is exactly why the build has to run afterwards.
     */
    private static String pinManagedVersion(String pom, ProposedUpgrade upgrade) {
        String group = upgrade.current().group();
        String artifact = upgrade.current().artifact();

        int managementStart = pom.indexOf("<dependencyManagement>");
        if (managementStart >= 0) {
            int managementEnd = pom.indexOf("</dependencyManagement>", managementStart);
            int closeDependencies = pom.lastIndexOf("</dependencies>", managementEnd);
            if (managementEnd < 0 || closeDependencies < managementStart) {
                throw new IllegalStateException("<dependencyManagement> in pom.xml has no <dependencies> block");
            }
            String indent = indentOf(pom, closeDependencies);
            int insertAt = closeDependencies - indent.length();
            return pom.substring(0, insertAt)
                    + dependencyElement(indent + "    ", group, artifact, upgrade.targetVersion())
                    + System.lineSeparator()
                    + pom.substring(insertAt);
        }

        // No dependencyManagement at all: add one just above <dependencies>, or failing
        // that at the end of the project — both are valid positions for Maven.
        int anchor = pom.indexOf("<dependencies>");
        if (anchor < 0) {
            anchor = pom.lastIndexOf("</project>");
        }
        if (anchor < 0) {
            throw new IllegalStateException("pom.xml has neither <dependencies> nor </project> to anchor a pin to");
        }
        String indent = indentOf(pom, anchor);
        int insertAt = anchor - indent.length();
        String block = indent + "<dependencyManagement>" + System.lineSeparator()
                + indent + "    <dependencies>" + System.lineSeparator()
                + dependencyElement(indent + "        ", group, artifact, upgrade.targetVersion())
                + System.lineSeparator()
                + indent + "    </dependencies>" + System.lineSeparator()
                + indent + "</dependencyManagement>" + System.lineSeparator()
                + System.lineSeparator();
        return pom.substring(0, insertAt) + block + pom.substring(insertAt);
    }

    /** A whole `<dependency>` element, every line prefixed with {@code pad}, no trailing newline. */
    private static String dependencyElement(String pad, String group, String artifact, String version) {
        String newline = System.lineSeparator();
        return pad + "<dependency>" + newline
                + pad + "    <groupId>" + group + "</groupId>" + newline
                + pad + "    <artifactId>" + artifact + ARTIFACT_ID + newline
                + pad + "    <version>" + version + "</version>" + newline
                + pad + "</dependency>";
    }

    private static boolean containsElement(String block, String element, String value) {
        return block.contains("<%s>%s</%s>".formatted(element, value, element));
    }

    /** Adds `<version>` immediately after `</artifactId>`, matching the surrounding indent. */
    private static String insertVersionElement(String pom, int blockStart, String block, String version) {
        int artifactEnd = block.indexOf(ARTIFACT_ID) + ARTIFACT_ID.length();
        int insertAt = blockStart + artifactEnd;
        String indent = indentOf(block, block.indexOf("<artifactId>"));
        return pom.substring(0, insertAt)
                + "%n%s<version>%s</version>".formatted(indent, version)
                + pom.substring(insertAt);
    }

    private static String indentOf(String text, int position) {
        int lineStart = text.lastIndexOf('\n', position) + 1;
        return text.substring(lineStart, Math.max(lineStart, position));
    }

    /** Rewrites `<jackson.version>2.12.0</jackson.version>`. Null when the property isn't here. */
    private static String replaceProperty(String pom, String property, String version) {
        Matcher matcher = Pattern.compile("(<%s>)\\s*[^<]*?\\s*(</%s>)"
                .formatted(Pattern.quote(property), Pattern.quote(property))).matcher(pom);
        // $1/$2 must stay live group references; only the injected version is quoted.
        return matcher.find()
                ? matcher.replaceFirst("$1" + Matcher.quoteReplacement(version) + "$2")
                : null;
    }

    /**
     * Best-effort, same contract as GradleParser: a build script is a program, and
     * anything computed at configuration time is invisible to a text edit.
     */
    static String applyGradleVersion(String script, ProposedUpgrade upgrade) {
        String coordinate = upgrade.current().group() + ":" + upgrade.current().artifact();

        Matcher literal = Pattern.compile("(['\"])" + Pattern.quote(coordinate) + ":([^'\"]+)\\1").matcher(script);
        if (literal.find()) {
            String declared = literal.group(2);
            Matcher interpolated = Pattern.compile("^\\$\\{?([\\w.]+)}?$").matcher(declared);
            if (interpolated.matches()) {
                String variable = interpolated.group(1);
                Matcher assignment = Pattern.compile(
                        "(\\b" + Pattern.quote(variable) + "\\s*=\\s*['\"])[^'\"]+(['\"])").matcher(script);
                if (assignment.find()) {
                    return assignment.replaceFirst("$1" + Matcher.quoteReplacement(upgrade.targetVersion()) + "$2");
                }
                throw new IllegalStateException(
                        "%s uses version variable '%s', which is not assigned in %s"
                                .formatted(coordinate, variable, "the build script"));
            }
            int start = literal.start(2);
            return script.substring(0, start) + upgrade.targetVersion() + script.substring(start + declared.length());
        }

        throw new IllegalStateException(
                "No declaration of %s with a version in the build script — it is managed by a platform/BOM, which needs a constraint rather than a version edit"
                        .formatted(coordinate));
    }

    // ── THE ORACLE ─────────────────────────────────────────────────────────────

    /**
     * Run the build and report honestly. Prefers the repo's own wrapper: that is the
     * version the project is known to work with, which is the entire point of it being
     * committed. Batch mode matters too — without it the output carries ANSI escapes
     * straight into the repair prompt.
     */
    BuildResult build() {
        List<String> command = tool == BuildTool.MAVEN
                ? List.of(wrapperOr("mvnw", "mvn"), "-B", "-ntp", "verify")
                : List.of(wrapperOr("gradlew", "gradle"), "--no-daemon", "--console=plain", "build");

        ProcessBuilder builder = new ProcessBuilder(command).directory(root.toFile());
        if (javaHome != null) {
            builder.environment().put("JAVA_HOME", javaHome.toString());
            builder.environment().put("PATH",
                    javaHome.resolve("bin") + java.io.File.pathSeparator + System.getenv("PATH"));
        }

        ProcessOutcome outcome = run(builder, BUILD_TIMEOUT);
        List<String> failingTests = parseFailingTests(tool, outcome.output());
        boolean passed = outcome.exitCode() == 0;

        log.info("Build {} (exit {}){}", passed ? "GREEN" : "RED", outcome.exitCode(),
                failingTests.isEmpty() ? "" : " — failing: " + String.join(", ", failingTests));

        return new BuildResult(passed, outcome.exitCode(), failingTests, tail(outcome.output()));
    }

    private String wrapperOr(String wrapper, String onPath) {
        Path candidate = root.resolve(wrapper);
        if (!Files.exists(candidate)) {
            return onPath;
        }
        // The exec bit survives a clone, but not every repo committed it set.
        if (!candidate.toFile().canExecute() && !candidate.toFile().setExecutable(true)) {
            log.warn("{} is not executable and cannot be made so — falling back to {}", wrapper, onPath);
            return onPath;
        }
        return candidate.toString();
    }

    /** Test names only. A compile failure has none, and the exit code already says so. */
    static List<String> parseFailingTests(BuildTool tool, String output) {
        Set<String> failing = new LinkedHashSet<>();
        if (tool == BuildTool.MAVEN) {
            collect(SUREFIRE_DETAIL, output, failing);
            if (failing.isEmpty()) {
                // Older surefire, or a run that only produced the summary block.
                collect(SUREFIRE_SUMMARY, output, failing);
            }
        } else {
            Matcher matcher = GRADLE_FAILURE.matcher(output);
            while (matcher.find()) {
                failing.add(matcher.group(1) + "." + matcher.group(2));
            }
        }
        return List.copyOf(failing);
    }

    private static void collect(Pattern pattern, String output, Set<String> into) {
        Matcher matcher = pattern.matcher(output);
        while (matcher.find()) {
            into.add(matcher.group(1));
        }
    }

    private static String tail(String output) {
        return output.length() <= MAX_OUTPUT_CHARS
                ? output
                : "[... %d earlier characters omitted ...]%n".formatted(output.length() - MAX_OUTPUT_CHARS)
                + output.substring(output.length() - MAX_OUTPUT_CHARS);
    }

    // ── CHECKPOINTS ────────────────────────────────────────────────────────────

    /**
     * Commit the current tree. Called on green, so the next upgrade starts from a
     * known-good state and an abandoned one has somewhere to rewind to.
     */
    String checkpoint(String message) {
        git("add", "-A");
        git("-c", "user.name=dependency-upgrader",
                "-c", "user.email=dependency-upgrader@localhost",
                "commit", "-m", message, "--allow-empty");
        lastGreenSha = head();
        return lastGreenSha;
    }

    /**
     * Throw away a failed attempt — the version bump and any repairs made chasing it.
     * Without this one unrepairable upgrade leaves a broken tree and every later build
     * is red for reasons that have nothing to do with the dependency being tested.
     */
    void revertToLastGreen() {
        if (lastGreenSha == null) {
            throw new IllegalStateException("No green checkpoint to revert to");
        }
        git("reset", "--hard", lastGreenSha);
        git("clean", "-fd");
        log.info("Reverted the working tree to {}", lastGreenSha);
    }

    /**
     * Publish the branch. The only outward-facing thing this class does, and the point
     * of no return — everything before it is confined to a temp directory.
     *
     * A shallow clone can still push a new branch, so --depth 1 costs nothing here.
     */
    void push(String token) {
        ProcessBuilder builder = new ProcessBuilder(List.of("git", "push", "-u", "origin", branch))
                .directory(root.toFile());
        authenticate(builder, token, root.getParent());

        ProcessOutcome outcome = run(builder, Duration.ofMinutes(5));
        if (outcome.exitCode() != 0) {
            String hint = outcome.output().contains("403") || outcome.output().contains("Permission")
                    ? " The token needs write access to this repository."
                    : "";
            throw new IllegalStateException("git push of %s failed (exit %d).%s%n%s"
                    .formatted(branch, outcome.exitCode(), hint, outcome.output()));
        }
        log.info("Pushed {}", branch);
    }

    /**
     * Commits this branch has that the base branch does not — i.e. actual upgrades.
     * Zero means there is nothing worth pushing, however well the run otherwise went.
     */
    int commitsAhead() {
        try {
            return Integer.parseInt(git("rev-list", "--count", baseBranch + ".." + branch).trim());
        } catch (NumberFormatException e) {
            log.warn("Cannot count commits on {} — assuming there are some", branch, e);
            return 1;
        }
    }

    private String head() {
        return git("rev-parse", "HEAD").trim();
    }

    private String git(String... args) {
        List<String> command = new ArrayList<>(List.of("git"));
        command.addAll(List.of(args));
        ProcessOutcome outcome = run(new ProcessBuilder(command).directory(root.toFile()), Duration.ofMinutes(2));
        if (outcome.exitCode() != 0) {
            throw new IllegalStateException("git %s failed (exit %d):%n%s"
                    .formatted(String.join(" ", args), outcome.exitCode(), outcome.output()));
        }
        return outcome.output();
    }

    // ── ACCESSORS ──────────────────────────────────────────────────────────────

    public Path root() {
        return root;
    }

    public String buildFile() {
        return buildFile;
    }

    public BuildResult baseline() {
        return baseline;
    }

    public String lastGreenSha() {
        return lastGreenSha;
    }

    public String branch() {
        return branch;
    }

    public String baseBranch() {
        return baseBranch;
    }

    @Override
    public void close() {
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    log.warn("Cannot delete {}", path, e);
                }
            });
        } catch (IOException e) {
            log.warn("Cannot clean up {}", root, e);
        }
    }

    @Override
    public String toString() {
        return "BuildWorkspace[%s, %s, branch=%s, jdk=%s]".formatted(root, buildFile, branch,
                javaHome == null ? "inherited" : javaHome.getFileName());
    }

    // ── PROCESS PLUMBING ───────────────────────────────────────────────────────

    private record ProcessOutcome(int exitCode, String output) {
    }

    /**
     * Output goes to a file rather than a pipe: a build can emit far more than a pipe
     * buffer holds, and draining it from this thread while also waiting on the timeout
     * is how you get a deadlock instead of a test result.
     */
    private static ProcessOutcome run(ProcessBuilder builder, Duration timeout) {
        Path logFile;
        try {
            logFile = Files.createTempFile("dependency-upgrade-log-", ".txt");
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create a log file", e);
        }

        builder.redirectErrorStream(true);
        builder.redirectOutput(logFile.toFile());
        try {
            Process process = builder.start();
            if (!process.waitFor(timeout.toSeconds(), TimeUnit.SECONDS)) {
                process.destroyForcibly();
                process.waitFor();
                return new ProcessOutcome(-1, read(logFile)
                        + "%n[killed after %d minutes]".formatted(timeout.toMinutes()));
            }
            return new ProcessOutcome(process.exitValue(), read(logFile));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot run " + String.join(" ", builder.command()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while running " + String.join(" ", builder.command()), e);
        } finally {
            try {
                Files.deleteIfExists(logFile);
            } catch (IOException e) {
                log.warn("Cannot delete {}", logFile, e);
            }
        }
    }

    private static String read(Path path) {
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read " + path, e);
        }
    }

    private static void write(Path path, String content) {
        try {
            Files.writeString(path, content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write " + path, e);
        }
    }
}