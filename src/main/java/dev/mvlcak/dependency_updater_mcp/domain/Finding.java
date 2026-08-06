package dev.mvlcak.dependency_updater_mcp.domain;

public record Finding(Dependency affected, String cveId, String severity, String fixedInVersion) {}
