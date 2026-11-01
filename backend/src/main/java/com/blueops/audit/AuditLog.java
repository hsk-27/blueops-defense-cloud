package com.blueops.audit;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant timestamp = Instant.now();

    @Column(nullable = false, length = 64)
    private String actor;

    @Column(nullable = false, length = 64)
    private String action; // LOGIN, INCIDENT_CREATE, STATUS_CHANGE, ACTION_APPROVE, ACTION_EXECUTE, etc.

    @Column(name = "target_entity", nullable = false, length = 64)
    private String targetEntity; // USER, INCIDENT, ASSET, IOC, RESPONSE_ACTION

    @Column(name = "target_id", length = 64)
    private String targetId;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Column(columnDefinition = "TEXT")
    private String details;

    public AuditLog() {}

    public AuditLog(String actor, String action, String targetEntity, String targetId, String sourceIp, String details) {
        this.timestamp = Instant.now();
        this.actor = actor;
        this.action = action;
        this.targetEntity = targetEntity;
        this.targetId = targetId;
        this.sourceIp = sourceIp;
        this.details = details;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }

    public String getTargetEntity() { return targetEntity; }
    public void setTargetEntity(String targetEntity) { this.targetEntity = targetEntity; }

    public String getTargetId() { return targetId; }
    public void setTargetId(String targetId) { this.targetId = targetId; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }
}
