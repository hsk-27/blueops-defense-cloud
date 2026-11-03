package com.blueops.advisory;

public enum AuthoritativeSource {
    NIST_SP_800_61R2("NIST SP 800-61 Rev. 2", "Computer Security Incident Handling Guide (National Institute of Standards and Technology)"),
    CISA_IR_PLAYBOOK("CISA IR Playbook", "Federal Cybersecurity Incident & Vulnerability Response Playbooks (CISA)"),
    MITRE_ATTACK_MITIGATION("MITRE ATT&CK", "MITRE Enterprise ATT&CK Defensive Mitigations Framework"),
    MITRE_D3FEND("MITRE D3FEND", "MITRE D3FEND Matrix for Defensive Cybersecurity Countermeasures"),
    SANS_PICERL("SANS PICERL", "SANS Incident Handler's Handbook & DFIR Standard Operating Procedures"),
    RFC_3227("IETF RFC 3227", "Guidelines for Evidence Collection and Archiving (Order of Volatility)");

    private final String standardName;
    private final String description;

    AuthoritativeSource(String standardName, String description) {
        this.standardName = standardName;
        this.description = description;
    }

    public String getStandardName() {
        return standardName;
    }

    public String getDescription() {
        return description;
    }
}
