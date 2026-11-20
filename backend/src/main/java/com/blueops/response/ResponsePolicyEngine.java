package com.blueops.response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Centralized Response Policy Engine (M6.3)
 * Enforces risk classification, blast radius bounds, protected asset containment,
 * input sanitization, separation-of-duties, and deny-by-default security policies.
 */
@Service
public class ResponsePolicyEngine {

    private static final Logger log = LoggerFactory.getLogger(ResponsePolicyEngine.class);

    private static final Set<String> PROTECTED_INFRASTRUCTURE = Set.of(
            "127.0.0.1", "0.0.0.0", "::1", "localhost", "gateway", "dns",
            "10.0.0.1", "10.0.0.2"
    );

    private static final Pattern SAFE_TARGET_PATTERN = Pattern.compile("^[a-zA-Z0-9.:/@_\\\\-]+$");

    private final ResponseTargetRepository targetRepository;

    @Value("${blueops.response.allow-live-execution:false}")
    private boolean allowLiveExecution;

    public ResponsePolicyEngine(ResponseTargetRepository targetRepository) {
        this.targetRepository = targetRepository;
    }

    /**
     * Evaluates a response proposal request against all security and operational policies.
     * Guaranteed fail-closed / deny-by-default behavior.
     */
    public PolicyEvaluationResultDto evaluate(ResponseActionDefinition actionDef,
                                              String targetIdentifier,
                                              ResponseExecutionMode requestedMode,
                                              String proposedBy,
                                              Map<String, Object> parameters) {
        List<String> violations = new ArrayList<>();
        ResponseRiskLevel riskLevel = actionDef.getRiskLevel() != null ? actionDef.getRiskLevel() : ResponseRiskLevel.MODERATE;

        // 1. Parameter presence and input validation
        if (targetIdentifier == null || targetIdentifier.trim().isEmpty()) {
            violations.add("Target identifier cannot be empty or null.");
            return new PolicyEvaluationResultDto(ResponsePolicyOutcome.INVALID, riskLevel, true, false,
                    "Invalid target parameter", violations, "Target undefined");
        }

        String cleanTarget = targetIdentifier.trim();

        // 2. CLI Option & Argument Injection Defense
        if (cleanTarget.startsWith("-")) {
            violations.add("Target cannot begin with a hyphen (CLI flag injection prevented).");
        }
        if (cleanTarget.contains(" ") || cleanTarget.contains("\t")) {
            violations.add("Target cannot contain whitespace (argument injection prevented).");
        }
        if (!SAFE_TARGET_PATTERN.matcher(cleanTarget).matches()) {
            violations.add("Target contains illegal shell or control metacharacters: " + cleanTarget);
        }

        // 3. Blast Radius & Protected Infrastructure Containment
        String lowerTarget = cleanTarget.toLowerCase(Locale.ROOT);
        if (PROTECTED_INFRASTRUCTURE.contains(lowerTarget)) {
            violations.add("Target matches protected infrastructure (" + cleanTarget + "). Disruption is strictly forbidden.");
        }

        // 4. Target Registry Verification & Trust State
        Optional<ResponseTargetRecord> targetOpt = targetRepository.findByIdentifierIgnoreCase(cleanTarget);
        if (targetOpt.isPresent()) {
            ResponseTargetRecord targetRecord = targetOpt.get();
            if (targetRecord.isProtected()) {
                violations.add("Target is registered as protected critical asset: " + targetRecord.getDisplayName());
            }
            if ("REVOKED".equalsIgnoreCase(targetRecord.getTrustStatus())) {
                violations.add("Target trust status is REVOKED. All response orchestration suspended.");
            }
            if ("CRITICAL".equalsIgnoreCase(targetRecord.getCriticality()) && riskLevel == ResponseRiskLevel.MODERATE) {
                // Elevate risk for critical targets
                riskLevel = ResponseRiskLevel.HIGH;
            }
        }

        if (!violations.isEmpty()) {
            log.warn("[POLICY DENIED] Proposed action [{}] against target [{}] failed validation: {}",
                    actionDef.getActionCode(), cleanTarget, violations);
            return new PolicyEvaluationResultDto(
                    ResponsePolicyOutcome.DENY,
                    riskLevel,
                    true,
                    false,
                    "Policy violation: " + String.join("; ", violations),
                    violations,
                    "Uncontained blast radius or forbidden target"
            );
        }

        // 5. Execution Mode Enforcement (Default Simulation Safety)
        if (requestedMode == ResponseExecutionMode.LIVE && !allowLiveExecution) {
            log.info("[POLICY SIMULATION_ONLY] Live mode requested for [{}] but live execution is disabled. Downgrading to SIMULATION_ONLY.", actionDef.getActionCode());
            return new PolicyEvaluationResultDto(
                    ResponsePolicyOutcome.SIMULATION_ONLY,
                    riskLevel,
                    true,
                    riskLevel == ResponseRiskLevel.HIGH || riskLevel == ResponseRiskLevel.CRITICAL,
                    "Live execution is disabled by global configuration; only simulation is authorized.",
                    violations,
                    "Contained strictly within simulation engine"
            );
        }

        // 6. Risk Level & Separation of Duties (SoD) Evaluation
        boolean requiresApproval = actionDef.isRequiresApproval() || riskLevel != ResponseRiskLevel.LOW;
        boolean sodRequired = (riskLevel == ResponseRiskLevel.HIGH || riskLevel == ResponseRiskLevel.CRITICAL);

        ResponsePolicyOutcome outcome = requiresApproval ? ResponsePolicyOutcome.REQUIRE_APPROVAL : ResponsePolicyOutcome.ALLOW;

        String blastAssessment = String.format("Risk: %s, Mode: %s, Reversible: %s",
                riskLevel.name(), requestedMode.name(), actionDef.isRollbackSupported() ? "YES" : "NO");

        return new PolicyEvaluationResultDto(
                outcome,
                riskLevel,
                requiresApproval,
                sodRequired,
                "Policy evaluation passed. " + (requiresApproval ? "Approval required prior to dispatch." : "Eligible for automatic dispatch."),
                violations,
                blastAssessment
        );
    }

    /**
     * Validates whether an approver is permitted to approve a given proposal.
     * Enforces Separation of Duties (proposer != approver for HIGH/CRITICAL actions).
     */
    public boolean canApprove(ResponseProposalRecord proposal, String approver) {
        if (approver == null || approver.trim().isEmpty()) {
            return false;
        }
        if (proposal == null) {
            return false;
        }

        ResponseRiskLevel risk = proposal.getRiskLevel();
        if (risk == ResponseRiskLevel.HIGH || risk == ResponseRiskLevel.CRITICAL) {
            // Separation of duties rule: Creator cannot approve their own high-risk proposal
            if (approver.trim().equalsIgnoreCase(proposal.getProposedBy().trim())) {
                log.warn("[SOD VIOLATION] User [{}] attempted to self-approve high-risk proposal [{}]",
                        approver, proposal.getProposalUuid());
                return false;
            }
        }
        return true;
    }
}
