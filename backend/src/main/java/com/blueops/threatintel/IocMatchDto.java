package com.blueops.threatintel;

import java.time.Instant;

public class IocMatchDto {
    private Long id;
    private Long iocId;
    private String iocValue;
    private String iocType;
    private String matchedValue;
    private Long assetId;
    private String assetHostname;
    private Instant eventTimestamp;
    private String opensearchDocId;
    private String matchedField;
    private Long incidentId;
    private Instant createdAt;

    public IocMatchDto() {}

    public IocMatchDto(IocMatch match) {
        if (match != null) {
            this.id = match.getId();
            if (match.getIoc() != null) {
                this.iocId = match.getIoc().getId();
                this.iocValue = match.getIoc().getIndicatorValue();
                this.iocType = match.getIoc().getIndicatorType() != null ? match.getIoc().getIndicatorType().name() : null;
            }
            this.matchedValue = match.getMatchedValue();
            if (match.getAsset() != null) {
                this.assetId = match.getAsset().getId();
                this.assetHostname = match.getAsset().getHostname();
            }
            this.eventTimestamp = match.getEventTimestamp();
            this.opensearchDocId = match.getOpensearchDocId();
            this.matchedField = match.getMatchedField();
            if (match.getIncident() != null) {
                this.incidentId = match.getIncident().getId();
            }
            this.createdAt = match.getCreatedAt();
        }
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getIocId() { return iocId; }
    public void setIocId(Long iocId) { this.iocId = iocId; }

    public String getIocValue() { return iocValue; }
    public void setIocValue(String iocValue) { this.iocValue = iocValue; }

    public String getIocType() { return iocType; }
    public void setIocType(String iocType) { this.iocType = iocType; }

    public String getMatchedValue() { return matchedValue; }
    public void setMatchedValue(String matchedValue) { this.matchedValue = matchedValue; }

    public Long getAssetId() { return assetId; }
    public void setAssetId(Long assetId) { this.assetId = assetId; }

    public String getAssetHostname() { return assetHostname; }
    public void setAssetHostname(String assetHostname) { this.assetHostname = assetHostname; }

    public Instant getEventTimestamp() { return eventTimestamp; }
    public void setEventTimestamp(Instant eventTimestamp) { this.eventTimestamp = eventTimestamp; }

    public String getOpensearchDocId() { return opensearchDocId; }
    public void setOpensearchDocId(String opensearchDocId) { this.opensearchDocId = opensearchDocId; }

    public String getMatchedField() { return matchedField; }
    public void setMatchedField(String matchedField) { this.matchedField = matchedField; }

    public Long getIncidentId() { return incidentId; }
    public void setIncidentId(Long incidentId) { this.incidentId = incidentId; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
