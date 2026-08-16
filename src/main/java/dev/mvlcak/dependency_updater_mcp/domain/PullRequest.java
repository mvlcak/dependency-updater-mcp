package dev.mvlcak.dependency_updater_mcp.domain;

import com.embabel.agent.domain.library.HasContent;

public record PullRequest(String url, String title, String body) implements HasContent {

    /**
     * The last word the caller hears. This is the goal's output object, so
     * PromptedTextCommunicator hands this string back as the MCP tool result —
     * whatever is written here is the whole final message, not a summary of it.
     */
    @Override
    public String getContent() {
        return """
                Dependency upgrade run finished.
                
                %s
                
                %s
                
                %s"""
                .formatted(url, title, body);
    }
}
