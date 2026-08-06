package dev.mvlcak.dependency_updater_mcp.config;

import dev.mvlcak.dependency_updater_mcp.tool.GitHubTools;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.UncheckedIOException;

@Configuration
public class ToolConfig {

    @Bean
    public GitHub gitHub(@Value("${github.token}") String token,
                         @Value("${github.endpoint}") String endpoint) {
        try {
            GitHubBuilder builder = new GitHubBuilder();
            if (!endpoint.isBlank()) {
                builder.withEndpoint(endpoint);
            }
            return token.isBlank()
                    // reads GITHUB_TOKEN / GITHUB_OAUTH / ~/.github, else anonymous (60 req/h)
                    ? GitHubBuilder.fromEnvironment().build()
                    : builder.withOAuthToken(token).build();
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