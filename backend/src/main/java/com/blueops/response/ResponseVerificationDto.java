package com.blueops.response;

import java.time.Instant;

public class ResponseVerificationDto {
    private Long id;
    private String verificationUuid;
    private Long proposalId;
    private Long executionId;
    private String status;
    private String verificationMethod;
    private String expectedOutcome;
    private String observedOutcome;
    private String evidencePayload;
    private Instant verifiedAt;
    private boolean isSimulation;

    public ResponseVerificationDto() {}

    public ResponseVerificationDto(ResponseVerificationRecord record) {
        this.id = record.getId();
        this.verificationUuid = record.getVerificationUuid();
        if (record.getProposal() != null) {
            this.proposalId = record.getProposal().getId();
        }
        this.executionId = record.getExecutionId();
        this.status = record.getStatus() != null ? record.getStatus().name() : "PENDING";
        this.verificationMethod = record.getVerificationMethod();
        this.expectedOutcome = record.getExpectedOutcome();
        this.observedOutcome = record.getObservedOutcome();
        this.evidencePayload = record.getEvidencePayload();
        this.verifiedAt = record.getVerifiedAt();
        this.isSimulation = record.isSimulation();
    }

    public Long getId() { return id; }
    public String getVerificationUuid() { return verificationUuid; }
    public Long getProposalId() { return proposalId; }
    public Long getExecutionId() { return executionId; }
    public String getStatus() { return status; }
    public String getVerificationMethod() { return verificationMethod; }
    public String getExpectedOutcome() { return expectedOutcome; }
    public String getObservedOutcome() { return observedOutcome; }
    public String getEvidencePayload() { return evidencePayload; }
    public Instant getVerifiedAt() { return verifiedAt; }
    public boolean isSimulation() { return isSimulation; }
}
