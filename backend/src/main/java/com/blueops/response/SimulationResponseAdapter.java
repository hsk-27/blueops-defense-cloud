package com.blueops.response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Simulation Response Adapter (M6.8)
 * Guarantees zero host mutation, executing entirely simulated actions for lab containment
 * and testing validation without touching host processes, network interfaces, or configurations.
 */
@Component
public class SimulationResponseAdapter implements ResponseAdapter {

    private static final Logger log = LoggerFactory.getLogger(SimulationResponseAdapter.class);

    @Override
    public String getAdapterType() {
        return "SIMULATION_CONTAINED_ADAPTER";
    }

    @Override
    public boolean supports(ResponseProposalRecord proposal) {
        return proposal.getExecutionMode() == ResponseExecutionMode.SIMULATION;
    }

    @Override
    public ResponseExecutionResult dispatch(ResponseProposalRecord proposal) {
        long startTime = System.currentTimeMillis();
        log.info("[SIMULATION DISPATCH] Executing simulated response [{}] for target [{}] (Proposal: {})",
                proposal.getActionCode(), proposal.getTargetIdentifier(), proposal.getProposalUuid());

        // Simulated latency
        long duration = 40L + (long) (Math.random() * 25);

        String payload = String.format(
                "{\"executionMode\":\"SIMULATION\",\"status\":\"SUCCESS\",\"actionCode\":\"%s\",\"actionName\":\"%s\",\"target\":\"%s\",\"targetType\":\"%s\",\"remediation\":\"Simulated policy applied successfully in safe lab containment.\",\"simulatedArtifact\":\"sim-ref-%s\"}",
                proposal.getActionCode(),
                proposal.getActionName(),
                proposal.getTargetIdentifier(),
                proposal.getTargetType(),
                proposal.getProposalUuid().substring(0, 8)
        );

        return new ResponseExecutionResult(
                true,
                200,
                "SIMULATION",
                "Simulated action applied and verified in contained lab sandbox",
                payload,
                duration
        );
    }
}
