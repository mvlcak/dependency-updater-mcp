package dev.mvlcak.dependency_updater_mcp.config;

import dev.mvlcak.dependency_updater_mcp.tool.GitHubTools;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.UncheckedIOException;

@Configuration
public class ToolConfig {

    private static final Logger log = LoggerFactory.getLogger(ToolConfig.class);

    /**
     * Blank endpoint means github.com — the client already defaults to api.github.com,
     * so it is only set for Enterprise (https://host/api/v3).
     *
     * Credentials and endpoint are chosen independently: picking up the token from the
     * environment must not also decide which host we talk to.
     */
    @Bean
    public GitHub gitHub(@Value("${github.token:}") String token,
                         @Value("${github.endpoint:}") String endpoint) {
        try {
            GitHubBuilder builder = token.isBlank()
                    // reads GITHUB_TOKEN / GITHUB_OAUTH / ~/.github, else anonymous (60 req/h)
                    ? GitHubBuilder.fromEnvironment()
                    : new GitHubBuilder().withOAuthToken(token);
            if (!endpoint.isBlank()) {
                builder = builder.withEndpoint(endpoint);
            }
            log.info("GitHub client: {}, credentials from {}",
                    endpoint.isBlank() ? "api.github.com" : endpoint,
                    token.isBlank() ? "the environment" : "github.token");
            return builder.build();
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot connect to GitHub", e);
        }
    }

    @Bean
    public GitHubTools gitHubTools(GitHub gitHub) {
        return GitHubTools.builder()
                .gitHub(gitHub)
                .build();
    }
}