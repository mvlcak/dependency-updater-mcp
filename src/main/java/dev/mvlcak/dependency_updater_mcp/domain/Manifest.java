package dev.mvlcak.dependency_updater_mcp.domain;

import java.util.List;

public record Manifest(String path, List<Dependency> dependencies) {}
