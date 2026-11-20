package com.blueops.response;

import java.util.List;

public class PolicyEvaluationResultDto {
    private ResponsePolicyOutcome outcome;
    private ResponseRiskLevel riskLevel;
    private boolean requiresApproval;
    private boolean isSeparationOfDutiesRequired;
    private String reason;
    private List<String> policyViolations;
    private String blastRadiusAssessment;

    public PolicyEvaluationResultDto() {}

    public PolicyEvaluationResultDto(ResponsePolicyOutcome outcome, ResponseRiskLevel riskLevel,
                                    boolean requiresApproval, boolean isSeparationOfDutiesRequired,
                                    String reason, List<String> policyViolations, String blastRadiusAssessment) {
        this.outcome = outcome;
        this.riskLevel = riskLevel;
        this.requiresApproval = requiresApproval;
        this.isSeparationOfDutiesRequired = isSeparationOfDutiesRequired;
        this.reason = reason;
        this.policyViolations = policyViolations;
        this.blastRadiusAssessment = blastRadiusAssessment;
    }

    public ResponsePolicyOutcome getOutcome() { return outcome; }
    public void setOutcome(ResponsePolicyOutcome outcome) { this.outcome = outcome; }

    public ResponseRiskLevel getRiskLevel() { return riskLevel; }
    public void setRiskLevel(ResponseRiskLevel riskLevel) { this.riskLevel = riskLevel; }

    public boolean isRequiresApproval() { return requiresApproval; }
    public void setRequiresApproval(boolean requiresApproval) { this.requiresApproval = requiresApproval; }

    public boolean isSeparationOfDutiesRequired() { return isSeparationOfDutiesRequired; }
    public void setSeparationOfDutiesRequired(boolean separationOfDutiesRequired) { isSeparationOfDutiesRequired = separationOfDutiesRequired; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public List<String> getPolicyViolations() { return policyViolations; }
    public void setPolicyViolations(List<String> policyViolations) { this.policyViolations = policyViolations; }

    public String getBlastRadiusAssessment() { return blastRadiusAssessment; }
    public void setBlastRadiusAssessment(String blastRadiusAssessment) { this.blastRadiusAssessment = blastRadiusAssessment; }
}
