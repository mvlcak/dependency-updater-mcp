package dev.mvlcak.dependency_updater_mcp.domain;

public record BuildResult(boolean passed, int exitCode, java.util.List<String> failingTests, String output) {}
