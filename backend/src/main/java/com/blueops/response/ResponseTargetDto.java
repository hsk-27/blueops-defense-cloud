package com.blueops.response;

public class ResponseTargetDto {
    private Long id;
    private String targetId;
    private String targetType;
    private String identifier;
    private String displayName;
    private String criticality;
    private String environment;
    private String trustStatus;
    private boolean isProtected;

    public ResponseTargetDto() {}

    public ResponseTargetDto(ResponseTargetRecord record) {
        this.id = record.getId();
        this.targetId = record.getTargetId();
        this.targetType = record.getTargetType();
        this.identifier = record.getIdentifier();
        this.displayName = record.getDisplayName();
        this.criticality = record.getCriticality();
        this.environment = record.getEnvironment();
        this.trustStatus = record.getTrustStatus();
        this.isProtected = record.isProtected();
    }

    public Long getId() { return id; }
    public String getTargetId() { return targetId; }
    public String getTargetType() { return targetType; }
    public String getIdentifier() { return identifier; }
    public String getDisplayName() { return displayName; }
    public String getCriticality() { return criticality; }
    public String getEnvironment() { return environment; }
    public String getTrustStatus() { return trustStatus; }
    public boolean isProtected() { return isProtected; }
}
