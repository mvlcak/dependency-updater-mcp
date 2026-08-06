package dev.mvlcak.dependency_updater_mcp.domain;

import org.kohsuke.github.GHRepository;

public record RepoRef(GHRepository repository, String buildTool) {}
