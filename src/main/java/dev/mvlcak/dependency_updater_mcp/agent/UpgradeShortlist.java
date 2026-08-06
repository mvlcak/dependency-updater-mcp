package dev.mvlcak.dependency_updater_mcp.agent;

import dev.mvlcak.dependency_updater_mcp.domain.Dependency;
import dev.mvlcak.dependency_updater_mcp.domain.Finding;
import dev.mvlcak.dependency_updater_mcp.domain.VulnerabilityReport;
import org.apache.maven.artifact.versioning.ComparableVersion;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Turns a VulnerabilityReport into a short, ranked list of candidate upgrades.
 *
 * Entirely deterministic — no LLM. A scan produces one Finding per (dependency, CVE),
 * which for a real repo means dozens of rows over a handful of dependencies. Sorting
 * and grouping that is arithmetic, and arithmetic is the one thing you should never
 * pay a model to do. What survives is the genuinely ambiguous part: given jackson at
 * 2.12.0, is the right move 2.12.6 (one CVE, tiny risk) or 2.18.9 (all eight, six
 * minor versions of drift)? That question goes to the LLM. This class does the rest.
 */
public final class UpgradeShortlist {

    /** Most severe first. Anything OSV didn't label lands at the bottom. */
    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN");

    /** Enough for the model to choose between; more just inflates the prompt. */
    private static final int MAX_CANDIDATES = 5;

    private UpgradeShortlist() {
    }

    /**
     * One vulnerable dependency and everything known about fixing it.
     *
     * @param fixVersions every version that closes at least one of this dependency's CVEs,
     *                    in Maven order — so the first entry is the smallest viable bump
     *                    and the last clears the most.
     */
    public record Candidate(Dependency dependency,
                            List<String> cveIds,
                            String worstSeverity,
                            List<String> fixVersions) {

        public String coordinate() {
            return dependency.group() + ":" + dependency.artifact();
        }

        /** Smallest bump that clears at least one CVE. */
        public String smallestFix() {
            return fixVersions.getFirst();
        }

        /** Highest known fix — clears the most, risks the most. */
        public String largestFix() {
            return fixVersions.getLast();
        }
    }

    /**
     * Groups findings by dependency and ranks them.
     *
     * @param alreadyAttempted coordinates ("group:artifact") already proposed in this run.
     *                         Read from the blackboard by the caller, so the loop never
     *                         proposes the same dependency twice.
     */
    public static List<Candidate> from(VulnerabilityReport report, Set<String> alreadyAttempted) {
        Map<String, List<Finding>> byCoordinate = new LinkedHashMap<>();
        for (Finding finding : report.findings()) {
            // No fix version means there is nothing to propose — a human has to decide.
            if (finding.fixedInVersion() == null || finding.affected().version() == null) {
                continue;
            }
            String coordinate = finding.affected().group() + ":" + finding.affected().artifact();
            if (alreadyAttempted.contains(coordinate)) {
                continue;
            }
            byCoordinate.computeIfAbsent(coordinate, key -> new ArrayList<>()).add(finding);
        }

        List<Candidate> candidates = new ArrayList<>();
        for (List<Finding> findings : byCoordinate.values()) {
            // Sorted set in Maven order: 2.12.7.1 above 2.12.7, 1.0-rc1 below 1.0.
            TreeSet<String> fixVersions = new TreeSet<>(Comparator.comparing(ComparableVersion::new));
            List<String> cveIds = new ArrayList<>();
            String worstSeverity = "UNKNOWN";

            for (Finding finding : findings) {
                fixVersions.add(finding.fixedInVersion());
                cveIds.add(finding.cveId());
                if (rankOf(finding.severity()) < rankOf(worstSeverity)) {
                    worstSeverity = finding.severity();
                }
            }
            candidates.add(new Candidate(
                    findings.getFirst().affected(),
                    List.copyOf(cveIds),
                    worstSeverity,
                    List.copyOf(fixVersions)));
        }

        candidates.sort(Comparator
                .comparingInt((Candidate candidate) -> rankOf(candidate.worstSeverity()))
                .thenComparing(candidate -> -candidate.cveIds().size()));

        return candidates.size() > MAX_CANDIDATES
                ? List.copyOf(candidates.subList(0, MAX_CANDIDATES))
                : List.copyOf(candidates);
    }

    private static int rankOf(String severity) {
        int index = SEVERITY_ORDER.indexOf(severity == null ? "UNKNOWN" : severity.toUpperCase());
        return index < 0 ? SEVERITY_ORDER.size() : index;
    }
}