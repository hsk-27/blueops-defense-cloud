package com.blueops.advisory;

import com.blueops.assets.Asset;
import com.blueops.common.exceptions.ResourceNotFoundException;
import com.blueops.findings.FindingDto;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.incidents.Incident;
import com.blueops.incidents.IncidentFinding;
import com.blueops.incidents.IncidentRepository;
import com.blueops.incidents.IncidentStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class IncidentAdvisoryService {

    private static final Logger log = LoggerFactory.getLogger(IncidentAdvisoryService.class);

    private final IncidentRepository incidentRepository;
    private final OpenSearchFindingAdapter findingAdapter;
    private final AdvisoryKnowledgeBase knowledgeBase;

    public IncidentAdvisoryService(
            IncidentRepository incidentRepository,
            OpenSearchFindingAdapter findingAdapter,
            AdvisoryKnowledgeBase knowledgeBase) {
        this.incidentRepository = incidentRepository;
        this.findingAdapter = findingAdapter;
        this.knowledgeBase = knowledgeBase;
    }

    @Transactional(readOnly = true)
    public List<IncidentRecommendationDto> generateRecommendations(Long incidentId) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found with ID: " + incidentId));

        Set<String> ruleCodes = new HashSet<>();
        Set<String> techniqueIds = new HashSet<>();
        String candidateAttackerIp = null;
        String candidateUsername = null;

        // Gather rule codes and techniques from attached findings
        for (IncidentFinding incFinding : incident.getFindings()) {
            ruleCodes.add(incFinding.getRuleCode());

            // Try to lookup rich FindingDto from OpenSearchFindingAdapter
            Optional<FindingDto> richFinding = findingAdapter.getFindingById(incFinding.getOpensearchFindingId());
            if (richFinding.isPresent()) {
                FindingDto f = richFinding.get();
                if (f.getMitreTechniqueId() != null) {
                    techniqueIds.add(f.getMitreTechniqueId());
                }
                if (f.getDetails() != null) {
                    Map<String, Object> details = f.getDetails();
                    if (details.containsKey("matched_indicator")) {
                        candidateAttackerIp = String.valueOf(details.get("matched_indicator"));
                    } else if (details.containsKey("source_ip")) {
                        candidateAttackerIp = String.valueOf(details.get("source_ip"));
                    } else if (details.containsKey("sourceIp")) {
                        candidateAttackerIp = String.valueOf(details.get("sourceIp"));
                    }

                    if (details.containsKey("user")) {
                        candidateUsername = String.valueOf(details.get("user"));
                    } else if (details.containsKey("targetUser")) {
                        candidateUsername = String.valueOf(details.get("targetUser"));
                    }
                }
            }
        }

        // Contextual fallbacks
        Asset asset = incident.getPrimaryAsset();
        String assetTarget = asset != null
                ? (asset.getIpAddress() != null ? asset.getIpAddress() : asset.getHostname())
                : "LAB-HOST";

        if (candidateAttackerIp == null && candidateUsername == null) {
            candidateAttackerIp = "198.51.100.24"; // Reference lab IOC
            candidateUsername = "compromised_user";
        }

        return evaluateRules(
                incident.getStatus(),
                incident.getSeverity().name(),
                ruleCodes,
                techniqueIds,
                assetTarget,
                candidateAttackerIp,
                candidateUsername
        );
    }

    public List<IncidentRecommendationDto> analyzeAdHoc(
            IncidentStatus status,
            String severity,
            Set<String> ruleCodes,
            Set<String> techniqueIds,
            String assetTarget,
            String attackerIp,
            String username) {
        return evaluateRules(status, severity, ruleCodes, techniqueIds, assetTarget, attackerIp, username);
    }

    private List<IncidentRecommendationDto> evaluateRules(
            IncidentStatus status,
            String severity,
            Set<String> ruleCodes,
            Set<String> techniqueIds,
            String assetTarget,
            String attackerIp,
            String username) {

        List<IncidentRecommendationDto> recommendations = new ArrayList<>();
        List<AdvisoryKnowledgeBase.AdvisoryRule> catalog = knowledgeBase.getCatalog();

        for (AdvisoryKnowledgeBase.AdvisoryRule rule : catalog) {
            boolean matchesRule = !Collections.disjoint(rule.triggerRuleCodes(), ruleCodes);
            boolean matchesTech = !Collections.disjoint(rule.triggerTechniques(), techniqueIds);

            // Special handling for Post-Incident
            boolean isPostIncidentRule = rule.phase() == AdvisoryPhase.POST_INCIDENT;
            boolean isIncidentResolved = (status == IncidentStatus.RESOLVED || status == IncidentStatus.FALSE_POSITIVE);

            if (matchesRule || matchesTech || (isPostIncidentRule && isIncidentResolved)) {
                String target = null;
                if ("P001".equals(rule.suggestedPlaybookCode())) {
                    target = attackerIp != null ? attackerIp : "198.51.100.24";
                } else if ("P002".equals(rule.suggestedPlaybookCode())) {
                    target = username != null ? username : "analyst";
                } else if ("P003".equals(rule.suggestedPlaybookCode()) || "P007".equals(rule.suggestedPlaybookCode())) {
                    target = assetTarget;
                }

                List<String> applicableTechniques = new ArrayList<>(rule.triggerTechniques());
                applicableTechniques.retainAll(techniqueIds);
                if (applicableTechniques.isEmpty()) {
                    applicableTechniques.addAll(rule.triggerTechniques());
                }

                IncidentRecommendationDto dto = new IncidentRecommendationDto(
                        rule.id(),
                        rule.title(),
                        rule.phase(),
                        rule.priority(),
                        rule.source(),
                        rule.citation(),
                        rule.rationaleTemplate(),
                        rule.steps(),
                        rule.suggestedPlaybookCode(),
                        rule.suggestedPlaybookName(),
                        target,
                        applicableTechniques
                );

                recommendations.add(dto);
            }
        }

        // If no specific rules matched (e.g. novel scenario), provide default NIST baseline
        if (recommendations.isEmpty()) {
            recommendations.add(new IncidentRecommendationDto(
                    "ADV-GEN-001",
                    "Execute Standard Scoping and Forensic Triage Protocol",
                    AdvisoryPhase.DETECTION_AND_ANALYSIS,
                    AdvisoryPriority.HIGH_PRIORITY,
                    AuthoritativeSource.NIST_SP_800_61R2,
                    "NIST SP 800-61r2 §3.2.6 (Incident Prioritization & Scoping)",
                    "For unclassified or emerging threats, NIST SP 800-61r2 mandates immediate functional and information impact assessment, identification of attacking vectors, and volatile memory acquisition.",
                    List.of(
                            "Identify all IP addresses, processes, and accounts linked to the incident.",
                            "Determine potential business impact and data sensitivity of the affected asset.",
                            "Acquire volatile endpoint evidence before rebooting or power cycling.",
                            "Document initial findings and establish an isolated investigation channel."
                    ),
                    "P007",
                    "Collect Endpoint Evidence Archive",
                    assetTarget,
                    List.of("T1059", "T1071")
            ));
        }

        // Sort by priority and lifecycle phase relevance
        recommendations.sort(Comparator
                .comparingInt((IncidentRecommendationDto r) -> r.getPriority().getRank())
                .thenComparing((IncidentRecommendationDto r) -> r.getPhase().ordinal())
        );

        return recommendations;
    }
}
