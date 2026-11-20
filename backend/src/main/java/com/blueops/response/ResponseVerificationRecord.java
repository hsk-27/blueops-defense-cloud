package com.blueops.response;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "response_verifications")
public class ResponseVerificationRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "verification_uuid", nullable = false, unique = true, length = 64)
    private String verificationUuid;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "proposal_id", nullable = false)
    private ResponseProposalRecord proposal;

    @Column(name = "execution_id")
    private Long executionId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private VerificationStatus status = VerificationStatus.PENDING;

    @Column(name = "verification_method", nullable = false, length = 64)
    private String verificationMethod;

    @Column(name = "expected_outcome", nullable = false, columnDefinition = "TEXT")
    private String expectedOutcome;

    @Column(name = "observed_outcome", nullable = false, columnDefinition = "TEXT")
    private String observedOutcome;

    @Column(name = "evidence_payload", columnDefinition = "TEXT")
    private String evidencePayload;

    @Column(name = "verified_at", nullable = false)
    private Instant verifiedAt = Instant.now();

    @Column(name = "is_simulation", nullable = false)
    private boolean isSimulation = true;

    public ResponseVerificationRecord() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getVerificationUuid() { return verificationUuid; }
    public void setVerificationUuid(String verificationUuid) { this.verificationUuid = verificationUuid; }

    public ResponseProposalRecord getProposal() { return proposal; }
    public void setProposal(ResponseProposalRecord proposal) { this.proposal = proposal; }

    public Long getExecutionId() { return executionId; }
    public void setExecutionId(Long executionId) { this.executionId = executionId; }

    public VerificationStatus getStatus() { return status; }
    public void setStatus(VerificationStatus status) { this.status = status; }

    public String getVerificationMethod() { return verificationMethod; }
    public void setVerificationMethod(String verificationMethod) { this.verificationMethod = verificationMethod; }

    public String getExpectedOutcome() { return expectedOutcome; }
    public void setExpectedOutcome(String expectedOutcome) { this.expectedOutcome = expectedOutcome; }

    public String getObservedOutcome() { return observedOutcome; }
    public void setObservedOutcome(String observedOutcome) { this.observedOutcome = observedOutcome; }

    public String getEvidencePayload() { return evidencePayload; }
    public void setEvidencePayload(String evidencePayload) { this.evidencePayload = evidencePayload; }

    public Instant getVerifiedAt() { return verifiedAt; }
    public void setVerifiedAt(Instant verifiedAt) { this.verifiedAt = verifiedAt; }

    public boolean isSimulation() { return isSimulation; }
    public void setSimulation(boolean simulation) { isSimulation = simulation; }
}
