package dev.mvlcak.dependency_updater_mcp.domain;

public record ProposedUpgrade(Dependency current, String targetVersion, String cveId, String rationale) {}
