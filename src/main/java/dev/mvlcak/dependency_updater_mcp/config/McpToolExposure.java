package dev.mvlcak.dependency_updater_mcp.config;

import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * This server exists to expose one thing: the dependency upgrade goal.
 *
 * <p>Embabel publishes more than that. Spring AI registers its {@code helloBanner}
 * tool, and the per-goal publisher adds the human-in-the-loop platform tools
 * ({@code _confirm}, {@code submitFormAndResumeProcess}) that this agent never uses —
 * it has no {@code ConfirmationRequest} or form binding anywhere. Every extra tool is
 * context the calling model has to read and a chance for it to pick the wrong one.
 *
 * <p>Embabel exposes its tools on {@code ContextRefreshedEvent}, so stripping the
 * rest on {@link ApplicationReadyEvent} runs afterwards and is the last word.
 * {@link UpgradeDependenciesTool} then re-registers the surviving tool with its
 * schemas, which is why the two are explicitly ordered.
 */
@Component
@Order(0)
public class McpToolExposure {

    private static final Logger log = LoggerFactory.getLogger(McpToolExposure.class);

    private static final List<String> EXPOSED_TOOLS = List.of("upgrade_dependencies");

    private final McpSyncServer mcpSyncServer;

    McpToolExposure(McpSyncServer mcpSyncServer) {
        this.mcpSyncServer = mcpSyncServer;
    }

    @EventListener(ApplicationReadyEvent.class)
    void keepOnlyExposedTools() {
        List<String> unwanted = mcpSyncServer.listTools().stream()
                .map(McpSchema.Tool::name)
                .filter(name -> !EXPOSED_TOOLS.contains(name))
                .toList();
        unwanted.forEach(mcpSyncServer::removeTool);
        log.info("MCP tools exposed: {} (removed {})",
                mcpSyncServer.listTools().stream().map(McpSchema.Tool::name).toList(),
                unwanted);
    }
}
