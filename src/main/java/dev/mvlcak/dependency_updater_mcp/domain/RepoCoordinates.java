package dev.mvlcak.dependency_updater_mcp.domain;

public record RepoCoordinates(String owner, String repository) {

    public String fullName() {
        return owner + "/" + repository;
    }
}
