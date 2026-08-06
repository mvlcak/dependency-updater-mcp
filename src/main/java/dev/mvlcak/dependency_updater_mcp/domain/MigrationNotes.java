package dev.mvlcak.dependency_updater_mcp.domain;

public record MigrationNotes(String summary, java.util.List<String> breakingChanges, java.util.List<String> sourceUrls) {}
