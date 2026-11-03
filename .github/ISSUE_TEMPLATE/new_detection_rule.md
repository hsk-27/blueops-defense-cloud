---
name: New Detection Rule Contribution
about: Propose a new Sigma detection rule or MITRE ATT&CK technique mapping
title: "[DETECTION] "
labels: ["detection-rule", "enhancement"]
assignees: ""
---

### Rule Overview
- **Rule Title:** 
- **Rule Code (Suggested):** e.g. D019
- **Log Source:** [e.g. windows_sysmon, linux_auditd, suricata]
- **Severity:** [LOW / MEDIUM / HIGH / CRITICAL]

### MITRE ATT&CK Mapping
- **Tactic:** [e.g. Execution, Persistence, Defense Evasion]
- **Technique ID & Name:** [e.g. T1059.001 - PowerShell]

### Threat Description & Adversary Behavior
Explain how adversaries utilize this technique and why current rules do not detect it.

### Proposed Detection Logic (Sigma YAML / Regex)
```yaml
title: My Detection Rule
id: D019
status: experimental
description: ...
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    ...
  condition: selection
```

### False Positive Analysis & Exclusions
What legitimate administrative tools or benign system behaviors might trigger this rule? How should they be filtered?
