package dev.mvlcak.dependency_updater_mcp.agent;

import dev.mvlcak.dependency_updater_mcp.domain.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.kohsuke.github.GHRepository;

import java.io.IOException;
import java.io.StringReader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static dev.mvlcak.dependency_updater_mcp.agent.DependencyUpgradeAgent.getContentOfFileFromRepo;


public final class PomParser {

    private PomParser() {
    }

    /** `${jackson.version}` style placeholders in a pom value. */
    private static final Pattern POM_PROPERTY = Pattern.compile("\\$\\{([^}]+)}");

    /**
     * Reads the raw pom.xml into a typed Model and flattens {@code <dependencies>}.
     *
     * This is the pom as written, not the effective pom: Maven itself would inherit
     * from the parent and resolve imported BOMs, which needs the whole reactor. So a
     * version can still come back null — spring-boot-starter-parent manages most
     * versions, and those are simply not present in the file. Same contract as the
     * Gradle parser: null means "managed elsewhere", not "broken".
     */
    static List<Dependency> parsePomAndGetDependencies(GHRepository repo) {
        return parsePomForDeps(getContentOfFileFromRepo(repo, "pom.xml"));
    }

    static List<Dependency> parsePomForDeps(String content) {
        MavenXpp3Reader reader = new MavenXpp3Reader();
        Model model;
        try {
            model = reader.read(new StringReader(content));
        } catch (IOException | XmlPullParserException e) {
            throw new RuntimeException("Cannot parse pom.xml", e);
        }

        Map<String, String> properties = collectPomProperties(model);
        Map<String, String> managedVersions = collectManagedVersions(model, properties);

        Set<Dependency> dependencies = new LinkedHashSet<>();
        for (org.apache.maven.model.Dependency declared : model.getDependencies()) {
            String group = resolveOrKeep(declared.getGroupId(), properties);
            String artifact = resolveOrKeep(declared.getArtifactId(), properties);
            String version = resolvePomValue(declared.getVersion(), properties);
            if (version == null) {
                // No version on the declaration — dependencyManagement in this same file
                // is the one place we can still find it without building the project.
                version = managedVersions.get(group + ":" + artifact);
            }
            dependencies.add(new Dependency(
                    group,
                    artifact,
                    version,
                    declared.getScope() == null ? "compile" : declared.getScope()));
        }
        return List.copyOf(dependencies);
    }

    /** User properties plus the handful of built-ins that show up in version strings. */
    private static Map<String, String> collectPomProperties(Model model) {
        Map<String, String> properties = new HashMap<>();
        model.getProperties().forEach((key, value) -> properties.put(String.valueOf(key), String.valueOf(value)));

        String version = model.getVersion() != null ? model.getVersion()
                : model.getParent() != null ? model.getParent().getVersion() : null;
        if (version != null) {
            properties.putIfAbsent("project.version", version);
            properties.putIfAbsent("pom.version", version);
        }
        String group = model.getGroupId() != null ? model.getGroupId()
                : model.getParent() != null ? model.getParent().getGroupId() : null;
        if (group != null) {
            properties.putIfAbsent("project.groupId", group);
        }
        return properties;
    }

    /** groupId:artifactId → version, from this file's own dependencyManagement block. */
    private static Map<String, String> collectManagedVersions(Model model, Map<String, String> properties) {
        if (model.getDependencyManagement() == null) {
            return Map.of();
        }
        Map<String, String> managed = new HashMap<>();
        for (org.apache.maven.model.Dependency declared : model.getDependencyManagement().getDependencies()) {
            String version = resolvePomValue(declared.getVersion(), properties);
            if (version != null) {
                managed.put(resolveOrKeep(declared.getGroupId(), properties)
                        + ":" + resolveOrKeep(declared.getArtifactId(), properties), version);
            }
        }
        return managed;
    }

    /** Substitutes `${...}`. Returns null when the value is absent or a property is unknown. */
    private static String resolvePomValue(String raw, Map<String, String> properties) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        Matcher matcher = POM_PROPERTY.matcher(raw);
        StringBuilder resolved = new StringBuilder();
        while (matcher.find()) {
            String value = properties.get(matcher.group(1));
            if (value == null) {
                return null;
            }
            matcher.appendReplacement(resolved, Matcher.quoteReplacement(value));
        }
        matcher.appendTail(resolved);
        return resolved.toString();
    }

    /** As above, but keeps the raw text — a group/artifact is never usefully null. */
    private static String resolveOrKeep(String raw, Map<String, String> properties) {
        String resolved = resolvePomValue(raw, properties);
        return resolved != null ? resolved : raw;
    }

}
