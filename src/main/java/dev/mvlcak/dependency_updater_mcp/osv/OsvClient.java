package dev.mvlcak.dependency_updater_mcp.osv;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import dev.mvlcak.dependency_updater_mcp.domain.Dependency;
import dev.mvlcak.dependency_updater_mcp.domain.Finding;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Queries OSV.dev for known vulnerabilities affecting a set of dependencies.
 */
@Component
public class OsvClient {

    private static final Logger log = LoggerFactory.getLogger(OsvClient.class);

    private static final int MAX_BATCH_SIZE = 1000;

    private static final String MAVEN_ECOSYSTEM = "Maven";

    private final RestClient restClient;

    public OsvClient(@Value("${osv.api-url:https://api.osv.dev}") String baseUrl) {
        this.restClient = RestClient.create(baseUrl);
    }

    /**
     * Returns one Finding per (dependency, vulnerability) pair. An empty list means the
     * dependencies are clean as far as OSV knows.
     *
     * Dependencies with a null version are skipped: OSV cannot answer "is this vulnerable"
     * without one. That is a real blind spot, not a formality — parent/BOM-managed versions
     * arrive here as null, so they are counted and logged rather than silently dropped.
     */
    public List<Finding> findVulnerabilities(List<Dependency> dependencies) {
        List<Dependency> versioned = dependencies.stream()
                .filter(dependency -> dependency.version() != null && !dependency.version().isBlank())
                .toList();

        int skipped = dependencies.size() - versioned.size();
        if (skipped > 0) {
            log.warn("Skipping {} of {} dependencies with no resolved version — these are NOT scanned",
                    skipped, dependencies.size());
        }
        if (versioned.isEmpty()) {
            return List.of();
        }

        List<Finding> findings = new ArrayList<>();
        Map<String, Vulnerability> cache = new HashMap<>();

        for (int start = 0; start < versioned.size(); start += MAX_BATCH_SIZE) {
            List<Dependency> chunk = versioned.subList(start, Math.min(start + MAX_BATCH_SIZE, versioned.size()));
            // Results come back positionally aligned with the queries we sent.
            List<BatchResult> results = queryBatch(chunk);

            for (int i = 0; i < chunk.size() && i < results.size(); i++) {
                BatchResult result = results.get(i);
                if (result == null || result.vulns() == null) {
                    continue;
                }
                Dependency dependency = chunk.get(i);
                for (VulnerabilityId vuln : result.vulns()) {
                    Vulnerability details = cache.computeIfAbsent(vuln.id(), this::fetchVulnerability);
                    if (details != null) {
                        findings.add(toFinding(dependency, details));
                    }
                }
            }
        }
        return List.copyOf(findings);
    }

    private List<BatchResult> queryBatch(List<Dependency> dependencies) {
        List<Query> queries = dependencies.stream()
                .map(dependency -> new Query(
                        dependency.version(),
                        new Package(coordinate(dependency), MAVEN_ECOSYSTEM)))
                .toList();

        BatchResponse response = restClient.post()
                .uri("/v1/querybatch")
                .body(new BatchRequest(queries))
                .retrieve()
                .body(BatchResponse.class);

        return response == null || response.results() == null ? List.of() : response.results();
    }

    private Vulnerability fetchVulnerability(String id) {
        try {
            return restClient.get()
                    .uri("/v1/vulns/{id}", id)
                    .retrieve()
                    .body(Vulnerability.class);
        } catch (RuntimeException e) {
            // One unreadable advisory must not sink the whole scan.
            log.warn("Could not fetch OSV vulnerability {}: {}", id, e.getMessage());
            return null;
        }
    }

    private Finding toFinding(Dependency dependency, Vulnerability vulnerability) {
        return new Finding(
                dependency,
                preferCveId(vulnerability),
                severityOf(vulnerability),
                lowestFixedVersionAbove(dependency, vulnerability));
    }

    /** OSV ids are mostly GHSA-*; the CVE is in aliases and is what a human recognises. */
    private String preferCveId(Vulnerability vulnerability) {
        if (vulnerability.aliases() != null) {
            for (String alias : vulnerability.aliases()) {
                if (alias.startsWith("CVE-")) {
                    return alias;
                }
            }
        }
        return vulnerability.id();
    }

    /**
     * GHSA-sourced entries — nearly all of Maven — carry a LOW/MODERATE/HIGH/CRITICAL label.
     * The `severity` array holds a raw CVSS vector, not a number, and turning that into a
     * score means implementing the CVSS formula, so anything without a label is UNKNOWN.
     */
    private String severityOf(Vulnerability vulnerability) {
        if (vulnerability.databaseSpecific() != null && vulnerability.databaseSpecific().severity() != null) {
            return vulnerability.databaseSpecific().severity();
        }
        return "UNKNOWN";
    }

    /**
     * The smallest version that clears this CVE without going backwards.
     *
     * An advisory usually lists several fixes, one per maintained branch (2.12.7.1 and
     * 2.13.4.2, say). We want the lowest that is still ahead of what the project uses —
     * the smallest bump, which is the least likely to break the build. Ordering is Maven's
     * own, so 2.12.7.1 correctly sorts above 2.12.7 and 1.0-rc1 below 1.0.
     *
     * Null when the advisory names no fix at all: real, and it means a human has to decide.
     */
    private String lowestFixedVersionAbove(Dependency dependency, Vulnerability vulnerability) {
        if (vulnerability.affected() == null) {
            return null;
        }
        String coordinate = coordinate(dependency);
        ComparableVersion current = new ComparableVersion(dependency.version());

        Set<String> fixedVersions = new LinkedHashSet<>();
        for (Affected affected : vulnerability.affected()) {
            if (affected.pkg() == null
                    || !coordinate.equalsIgnoreCase(affected.pkg().name())
                    || affected.ranges() == null) {
                continue;
            }
            for (Range range : affected.ranges()) {
                if (range.events() == null) {
                    continue;
                }
                for (Event event : range.events()) {
                    if (event.fixed() != null) {
                        fixedVersions.add(event.fixed());
                    }
                }
            }
        }

        return fixedVersions.stream()
                .filter(fixed -> new ComparableVersion(fixed).compareTo(current) > 0)
                .min(Comparator.comparing(ComparableVersion::new))
                .orElse(null);
    }

    /** OSV names Maven packages "groupId:artifactId". */
    private String coordinate(Dependency dependency) {
        return dependency.group() + ":" + dependency.artifact();
    }

    // ── WIRE FORMAT ────────────────────────────────────────────────────────────────
    // Only the fields we actually consume; everything else in the response is ignored.

    record BatchRequest(List<Query> queries) {}

    record Query(String version, @JsonProperty("package") Package pkg) {}

    record Package(String name, String ecosystem) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record BatchResponse(List<BatchResult> results) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record BatchResult(List<VulnerabilityId> vulns) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record VulnerabilityId(String id) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Vulnerability(String id,
                         List<String> aliases,
                         String summary,
                         List<Affected> affected,
                         @JsonProperty("database_specific") DatabaseSpecific databaseSpecific) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Affected(@JsonProperty("package") Package pkg, List<Range> ranges) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Range(String type, List<Event> events) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Event(String introduced, String fixed) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record DatabaseSpecific(String severity) {}
}
