package dev.mvlcak.dependency_updater_mcp.domain;

/**
 * What the LLM is allowed to decide in chooseUpgrade: which dependency, and how far.
 *
 * Deliberately not a ProposedUpgrade. The model picks a coordinate and a target from a
 * shortlist we built; the code then looks up the real Dependency and CVE ids. So a
 * hallucinated version or a package that was never on the list cannot reach the build.
 */
public record UpgradeChoice(String coordinate, String targetVersion, String rationale) {}