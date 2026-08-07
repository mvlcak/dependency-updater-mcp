package dev.mvlcak.dependency_updater_mcp;

import com.embabel.agent.core.Action;
import com.embabel.agent.core.Agent;
import com.embabel.agent.core.AgentPlatform;
import com.embabel.agent.core.Goal;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the failure mode where the planner gives up before running anything.
 *
 * A @Condition used as a precondition is invisible to the planner unless some action
 * declares it in `post`. Miss one and the whole plan is unreachable: the process ends
 * with History (0), and AgentInvocation.invoke() surfaces it only as
 * "get(...) must not be null" — a null result with no clue as to the cause.
 *
 * This asserts that every condition a goal needs is produced by some action, which is
 * exactly what the planner complains about at runtime.
 */
@SpringBootTest
class PlanReachabilityTest {

    @Autowired
    AgentPlatform platform;

    @Test
    void everyGoalPreconditionIsProducedBySomeAction() {
        for (Agent agent : platform.agents()) {
            Set<String> achievable = new LinkedHashSet<>();
            for (Action action : agent.getActions()) {
                achievable.addAll(trueKeys(action.getEffects()));
            }

            for (Goal goal : agent.getGoals()) {
                for (String required : trueKeys(goal.getPreconditions())) {
                    assertTrue(achievable.contains(required),
                            () -> """
                                    Goal '%s' of agent '%s' requires '%s', which no action produces.
                                    The planner cannot reach the goal, so the process will run nothing at all.
                                    Add it to the `post` of whichever action achieves it.
                                    Produced by actions: %s"""
                                    .formatted(goal.getName(), agent.getName(), required, achievable));
                }
            }
        }
    }

    /** Preconditions and effects are keyed by condition name; we only care about the positive ones. */
    private Set<String> trueKeys(Map<String, ?> spec) {
        Set<String> keys = new LinkedHashSet<>();
        spec.forEach((key, determination) -> {
            if ("TRUE".equals(String.valueOf(determination))) {
                keys.add(key);
            }
        });
        return keys;
    }
}
