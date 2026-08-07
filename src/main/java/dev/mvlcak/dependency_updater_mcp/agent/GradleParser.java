package dev.mvlcak.dependency_updater_mcp.agent;

import dev.mvlcak.dependency_updater_mcp.domain.Dependency;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class GradleParser {

    private GradleParser() {
    }

    /**
     * Gradle configurations that declare a real dependency. Used as a whitelist so we
     * don't pick up `id "com.foo.bar"` in the plugins block or similar noise.
     */
    private static final Set<String> GRADLE_CONFIGURATIONS = Set.of(
            "implementation", "dev/mvlcak/dependency_updater_mcp/api", "compileOnly", "compileOnlyApi", "runtimeOnly",
            "compile", "runtime", "providedCompile", "providedRuntime", "developmentOnly",
            "annotationProcessor", "kapt", "classpath",
            "testImplementation", "testApi", "testCompileOnly", "testRuntimeOnly",
            "testCompile", "testRuntime", "testAnnotationProcessor",
            "integrationTestImplementation", "integrationTestRuntimeOnly");

    /** Line and block comments — stripped before matching so commented-out deps don't count. */
    private static final Pattern COMMENTS = Pattern.compile("//[^\n]*|/\\*.*?\\*/", Pattern.DOTALL);

    /** `def x = "1.2.3"`, `val x = '1.2.3'`, or a bare `x = "1.2.3"` inside an ext block. */
    private static final Pattern VARIABLE = Pattern.compile(
            "(?:def|val|var)?\\s*\\b(\\w+)\\s*=\\s*['\"]([^'\"]+)['\"]");

    /** `implementation 'g:a:v'`, `api(\"g:a:v\")`, `testImplementation \"g:a\"` (version optional). */
    private static final Pattern GAV = Pattern.compile(
            "\\b(\\w+)\\s*(?:\\(\\s*)?['\"]([^'\"\\s:@]+):([^'\"\\s:@]+)(?::([^'\"\\s:@]+))?(?:@\\w+)?['\"]");

    /** `implementation group: 'g', name: 'a', version: 'v'` — the old map notation. */
    private static final Pattern MAP_NOTATION = Pattern.compile(
            "\\b(\\w+)\\s*(?:\\(\\s*)?group\\s*:\\s*['\"]([^'\"]+)['\"]\\s*,\\s*name\\s*:\\s*['\"]([^'\"]+)['\"]"
                    + "(?:\\s*,\\s*version\\s*:\\s*['\"]([^'\"]+)['\"])?");

    /** `$ver` or `${ver}` inside a version string. */
    private static final Pattern INTERPOLATION = Pattern.compile("\\$\\{?([\\w.]+)}?");

    /**
     * Static, best-effort parse of a Gradle build script.
     *
     * A build.gradle is a Groovy program and a build.gradle.kts a Kotlin one, so this
     * cannot be exact — anything computed at configuration time is invisible to us.
     * It handles the declarations people actually write: string notation in both DSLs,
     * the legacy map notation, and `$var` versions defined in the same file.
     *
     * A null version means "declared without one" — BOM/platform managed, or an
     * interpolation we could not resolve. Callers must not treat it as an error.
     */
    static List<Dependency> parseGradleForDeps(String content) {
        String source = COMMENTS.matcher(content).replaceAll("");
        Map<String, String> variables = collectVariables(source);

        // LinkedHashSet: the same GAV is often declared twice (e.g. api + testImplementation
        // in different blocks), and declaration order is worth keeping for readability.
        Set<Dependency> dependencies = new LinkedHashSet<>();

        Matcher gav = GAV.matcher(source);
        while (gav.find()) {
            String configuration = gav.group(1);
            if (!GRADLE_CONFIGURATIONS.contains(configuration)) {
                continue;
            }
            dependencies.add(new Dependency(
                    gav.group(2),
                    gav.group(3),
                    resolveVersion(gav.group(4), variables),
                    normaliseScope(configuration)));
        }

        Matcher map = MAP_NOTATION.matcher(source);
        while (map.find()) {
            String configuration = map.group(1);
            if (!GRADLE_CONFIGURATIONS.contains(configuration)) {
                continue;
            }
            dependencies.add(new Dependency(
                    map.group(2),
                    map.group(3),
                    resolveVersion(map.group(4), variables),
                    normaliseScope(configuration)));
        }

        return List.copyOf(dependencies);
    }

    private static Map<String, String> collectVariables(String source) {
        Map<String, String> variables = new HashMap<>();
        Matcher matcher = VARIABLE.matcher(source);
        while (matcher.find()) {
            variables.put(matcher.group(1), matcher.group(2));
        }
        return variables;
    }

    /** Substitutes `$var` / `${var}`. Returns null when the version is absent or unresolvable. */
    private static String resolveVersion(String rawVersion, Map<String, String> variables) {
        if (rawVersion == null || rawVersion.isBlank()) {
            return null;
        }
        Matcher matcher = INTERPOLATION.matcher(rawVersion);
        StringBuilder resolved = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1);
            // Also try the last segment, so ext.springVersion matches a springVersion binding.
            String value = variables.get(name);
            if (value == null && name.contains(".")) {
                value = variables.get(name.substring(name.lastIndexOf('.') + 1));
            }
            if (value == null) {
                return null;
            }
            matcher.appendReplacement(resolved, Matcher.quoteReplacement(value));
        }
        matcher.appendTail(resolved);
        return resolved.toString();
    }

    /** Maps a Gradle configuration onto a Maven-style scope, so both parsers agree. */
    private static String normaliseScope(String configuration) {
        if (configuration.startsWith("test") || configuration.startsWith("integrationTest")) {
            return "test";
        }
        return switch (configuration) {
            case "classpath" -> "build";
            case "compileOnly", "compileOnlyApi", "annotationProcessor", "kapt",
                 "providedCompile", "providedRuntime", "developmentOnly" -> "provided";
            case "runtimeOnly", "runtime" -> "runtime";
            default -> "compile";
        };
    }
}
