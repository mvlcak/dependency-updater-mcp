package dev.mvlcak.dependency_updater_mcp.config;

import com.embabel.agent.api.common.autonomy.AgentProcessExecution;
import com.embabel.agent.api.common.autonomy.Autonomy;
import com.embabel.agent.api.common.autonomy.ProcessWaitingException;
import com.embabel.agent.core.Agent;
import com.embabel.agent.core.Goal;
import com.embabel.agent.core.ProcessOptions;
import com.embabel.agent.tools.agent.PromptedTextCommunicator;
import dev.mvlcak.dependency_updater_mcp.domain.PullRequest;
import dev.mvlcak.dependency_updater_mcp.domain.RepoCoordinates;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Re-registers the upgrade goal as a hand-built MCP tool, so it can carry an output schema.
 *
 * <p>Embabel's tool is published through {@code McpToolUtils.toSyncToolSpecification}, which
 * builds every {@link McpSchema.Tool} from a Spring AI {@code ToolDefinition} — a type that
 * knows only name, description and input schema. There is no seam to hang an output schema
 * on: not on Embabel's {@code Tool.Definition}, and not on Spring AI's {@code ToolDefinition}.
 * The MCP SDK itself supports all of it, so the only way through is to skip that conversion
 * and talk to {@link McpSyncServer} directly.
 *
 * <p>The cost of bypassing is that {@code GoalTool} is no longer in the loop, so the running
 * of the goal is reproduced here. The gain is that the typed {@link PullRequest} is still in
 * hand when the result is built — Embabel's path flattens it to a string before the MCP layer
 * ever sees it, which is precisely why it has nothing structured to return.
 */
@Component
@Order(10)
public class UpgradeDependenciesTool {

    private static final Logger log = LoggerFactory.getLogger(UpgradeDependenciesTool.class);

    static final String TOOL_NAME = "upgrade_dependencies";

    private static final Map<String, Object> INPUT_SCHEMA = objectSchema(
            properties(
                    "owner", string("GitHub user or organisation that owns the repository, e.g. \"spring-projects\"."),
                    "repository", string("Repository name alone, without the owner prefix, e.g. \"spring-boot\".")),
            "owner", "repository");

    private static final Map<String, Object> OUTPUT_SCHEMA = objectSchema(
            properties(
                    "url", string("URL of the draft pull request, or a note that nothing was pushed when the server runs with pushing disabled."),
                    "title", string("Title of the pull request."),
                    "body", string("Body of the pull request, in Markdown, ending with a table of every upgrade applied.")),
            "url", "title", "body");

    private final Autonomy autonomy;

    private final McpSyncServer mcpSyncServer;

    UpgradeDependenciesTool(Autonomy autonomy, McpSyncServer mcpSyncServer) {
        this.autonomy = autonomy;
        this.mcpSyncServer = mcpSyncServer;
    }

    @EventListener(ApplicationReadyEvent.class)
    void republishWithSchemas() {
        Goal goal = autonomy.getAgentPlatform().getGoals().stream()
                .filter(candidate -> TOOL_NAME.equals(candidate.getExport().getName()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "No goal exported as '%s' — check @AchievesGoal on DependencyUpgradeAgent".formatted(TOOL_NAME)));

        // Embabel already published its own version of this tool under the same name.
        if (mcpSyncServer.listTools().stream().anyMatch(tool -> TOOL_NAME.equals(tool.name()))) {
            mcpSyncServer.removeTool(TOOL_NAME);
        }

        McpSchema.Tool tool = McpSchema.Tool.builder()
                .name(TOOL_NAME)
                .title("Upgrade vulnerable dependencies")
                .description(goal.getDescription())
                .inputSchema(INPUT_SCHEMA)
                .outputSchema(OUTPUT_SCHEMA)
                .annotations(McpSchema.ToolAnnotations.builder()
                        .readOnlyHint(false)
                        // Nothing existing is rewritten: the work lands on a new branch and
                        // arrives as a draft PR that a human still has to merge.
                        .destructiveHint(false)
                        .idempotentHint(false)
                        // Reaches GitHub, OSV.dev, and the open web for migration notes.
                        .openWorldHint(true)
                        .build())
                .build();

        mcpSyncServer.addTool(new McpServerFeatures.SyncToolSpecification(tool, this::call));
        log.info("Republished MCP tool '{}' with input and output schemas", TOOL_NAME);
    }

    /**
     * Runs the goal directly, in place of {@code GoalTool.call}, and returns both the prose
     * the caller reads and the structured object the output schema promises.
     */
    private McpSchema.CallToolResult call(McpSyncServerExchange exchange, McpSchema.CallToolRequest request) {
        Map<String, Object> arguments = request.arguments() == null ? Map.of() : request.arguments();
        String owner = text(arguments.get("owner"));
        String repository = text(arguments.get("repository"));
        if (owner.isBlank() || repository.isBlank()) {
            return error("Both 'owner' and 'repository' are required, and neither may be blank.");
        }

        RepoCoordinates coordinates = new RepoCoordinates(owner, repository);
        Goal goal = autonomy.getAgentPlatform().getGoals().stream()
                .filter(candidate -> TOOL_NAME.equals(candidate.getExport().getName()))
                .findFirst()
                .orElseThrow();

        log.info("MCP tool '{}' invoked for {}", TOOL_NAME, coordinates.fullName());
        try {
            Agent agent = autonomy.createGoalAgent(coordinates, autonomy.getAgentPlatform(), goal, false);
            AgentProcessExecution execution = autonomy.runAgent(coordinates, new ProcessOptions(), agent);
            return success(execution.getOutput());
        } catch (Exception e) {
            // ProcessWaitingException extends Exception and runAgent carries no @Throws,
            // so javac refuses a catch clause for it — hence the instanceof.
            // No action in this agent awaits a human, and the platform tools that would
            // resume a waiting process are stripped from this server, so a caller could
            // not act on one anyway. Report it rather than hang.
            if (e instanceof ProcessWaitingException waiting) {
                return error(PromptedTextCommunicator.INSTANCE.communicateAwaitable(goal, waiting));
            }
            log.error("Upgrade run for {} failed", coordinates.fullName(), e);
            return error("Upgrade run for %s failed: %s".formatted(coordinates.fullName(), e.getMessage()));
        }
    }

    /**
     * Structured content must match {@link #OUTPUT_SCHEMA}, so it is built from the record's
     * components rather than serialised wholesale — {@code getContent()} is prose for the text
     * block and has no place in the structured payload.
     */
    private McpSchema.CallToolResult success(Object output) {
        if (!(output instanceof PullRequest pullRequest)) {
            // Reachable only if the goal's return type changes without this being updated.
            log.warn("Goal returned {} rather than a PullRequest — omitting structured content",
                    output == null ? "null" : output.getClass().getName());
            return McpSchema.CallToolResult.builder()
                    .addTextContent(String.valueOf(output))
                    .build();
        }

        Map<String, Object> structured = new LinkedHashMap<>();
        structured.put("url", pullRequest.url());
        structured.put("title", pullRequest.title());
        structured.put("body", pullRequest.body());

        return McpSchema.CallToolResult.builder()
                .addTextContent(pullRequest.getContent())
                .structuredContent(structured)
                .build();
    }

    private McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder()
                .addTextContent(message)
                .isError(true)
                .build();
    }

    private static String text(Object value) {
        return value == null ? "" : value.toString().trim();
    }

    private static Map<String, Object> string(String description) {
        return Map.of("type", "string", "description", description);
    }

    /**
     * Insertion-ordered so clients render the fields in the order they are declared above.
     */
    private static Map<String, Object> properties(Object... nameThenSchema) {
        Map<String, Object> properties = new LinkedHashMap<>();
        for (int i = 0; i < nameThenSchema.length; i += 2) {
            properties.put((String) nameThenSchema[i], nameThenSchema[i + 1]);
        }
        return properties;
    }

    private static Map<String, Object> objectSchema(Map<String, Object> properties, String... required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("required", List.of(required));
        return schema;
    }
}
