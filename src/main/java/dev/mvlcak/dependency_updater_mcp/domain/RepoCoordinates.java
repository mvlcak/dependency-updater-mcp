package dev.mvlcak.dependency_updater_mcp.domain;

/**
 * What the LLM is allowed to decide about which repository to work on: a name.
 *
 * Deliberately two strings. The obvious shortcut — asking the model to produce a
 * GHRepository directly — cannot work: that is a live API object with an internal
 * back-reference to the HTTP client, so anything the model "fills in" arrives with
 * no client attached and every later call against it fails. The model names the
 * repo; the GitHub client resolves it.
 */
public record RepoCoordinates(String owner, String name) {

    public String fullName() {
        return owner + "/" + name;
    }
}
