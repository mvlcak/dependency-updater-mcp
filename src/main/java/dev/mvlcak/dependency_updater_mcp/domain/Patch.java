package dev.mvlcak.dependency_updater_mcp.domain;

public record Patch(java.util.List<String> filesChanged, String explanation) {}
