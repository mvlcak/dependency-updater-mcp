package dev.mvlcak.dependency_updater_mcp.tool;

import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.io.IOException;
import java.io.UncheckedIOException;

public class GitHubTools {

    private final GitHub gitHub;

    private GitHubTools(GitHub gitHub) {
        this.gitHub = gitHub;
    }

    @Tool(description = "Tool for searching in GitHub by repositoryName and owner")
    public GHRepository getRepoRefFromGithub(@ToolParam(description = "repository name in github to search for") String repositoryName,
                                        @ToolParam(description = "owner name of repository") String owner) {
        try {
            return gitHub.getRepository(owner + "/" + repositoryName);
        } catch (IOException e) {
            throw new UncheckedIOException(
                    "Cannot read GitHub repository " + owner + "/" + repositoryName, e);
        }
    }



    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private GitHub gitHub;

        /** The shared client, built in ToolConfig. */
        public Builder gitHub(GitHub gitHub) {
            this.gitHub = gitHub;
            return this;
        }

        public GitHubTools build() {
            if (gitHub == null) {
                throw new IllegalStateException("gitHub client is required");
            }
            return new GitHubTools(gitHub);
        }
    }
}