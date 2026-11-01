package com.blueops.incidents;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "incident_status_history")
public class IncidentStatusHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id", nullable = false)
    private Incident incident;

    @Column(name = "from_status", nullable = false, length = 32)
    private String fromStatus;

    @Column(name = "to_status", nullable = false, length = 32)
    private String toStatus;

    @Column(nullable = false, length = 64)
    private String actor;

    @Column(columnDefinition = "TEXT")
    private String reason;

    @Column(name = "transitioned_at", nullable = false, updatable = false)
    private Instant transitionedAt = Instant.now();

    public IncidentStatusHistory() {}

    public IncidentStatusHistory(Incident incident, String fromStatus, String toStatus, String actor, String reason) {
        this.incident = incident;
        this.fromStatus = fromStatus;
        this.toStatus = toStatus;
        this.actor = actor;
        this.reason = reason;
        this.transitionedAt = Instant.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Incident getIncident() { return incident; }
    public void setIncident(Incident incident) { this.incident = incident; }

    public String getFromStatus() { return fromStatus; }
    public void setFromStatus(String fromStatus) { this.fromStatus = fromStatus; }

    public String getToStatus() { return toStatus; }
    public void setToStatus(String toStatus) { this.toStatus = toStatus; }

    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public Instant getTransitionedAt() { return transitionedAt; }
    public void setTransitionedAt(Instant transitionedAt) { this.transitionedAt = transitionedAt; }
}
