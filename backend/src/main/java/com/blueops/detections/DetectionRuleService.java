package com.blueops.detections;

import com.blueops.audit.AuditService;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class DetectionRuleService {

    private final DetectionRuleRepository ruleRepository;
    private final AuditService auditService;

    @Autowired
    public DetectionRuleService(DetectionRuleRepository ruleRepository, @Autowired(required = false) AuditService auditService) {
        this.ruleRepository = ruleRepository;
        this.auditService = auditService;
    }

    public DetectionRuleService(DetectionRuleRepository ruleRepository) {
        this(ruleRepository, null);
    }

    @Transactional(readOnly = true)
    public List<DetectionRuleDto> getAllRules() {
        return ruleRepository.findAll().stream()
                .map(DetectionRuleDto::new)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public DetectionRuleDto getRuleById(Long id) {
        DetectionRule rule = ruleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("DetectionRule", "id", id));
        return new DetectionRuleDto(rule);
    }

    @Transactional
    public DetectionRuleDto updateRuleStatus(Long id, String status) {
        DetectionRule rule = ruleRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("DetectionRule", "id", id));

        if (!status.equals("ACTIVE") && !status.equals("DISABLED") && !status.equals("TESTING")) {
            throw new InvalidActionException("Invalid rule status. Must be ACTIVE, DISABLED, or TESTING");
        }

        rule.setStatus(status);
        rule.setUpdatedAt(Instant.now());
        DetectionRule saved = ruleRepository.save(rule);
        if (auditService != null) {
            auditService.recordEvent("system", "DETECTION_RULE_STATUS_CHANGE", "DetectionRule", String.valueOf(saved.getId()), null,
                    "Rule " + saved.getRuleCode() + " (" + saved.getName() + ") changed status to " + status);
        }
        return new DetectionRuleDto(saved);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getDetectionsSummary() {
        Map<String, Object> summary = new HashMap<>();
        long total = ruleRepository.count();
        long active = ruleRepository.countByStatus("ACTIVE");
        long disabled = ruleRepository.countByStatus("DISABLED");
        long testing = ruleRepository.countByStatus("TESTING");

        summary.put("totalRules", total);
        summary.put("activeRules", active);
        summary.put("disabledRules", disabled);
        summary.put("testingRules", testing);
        summary.put("windowsRules", ruleRepository.findByLogSource("windows_sysmon").size());
        summary.put("linuxRules", ruleRepository.findByLogSource("linux_auditd").size());
        summary.put("networkRules", ruleRepository.findByLogSource("suricata").size());

        return summary;
    }
}
