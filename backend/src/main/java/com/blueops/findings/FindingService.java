package com.blueops.findings;

import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class FindingService {

    private static final Set<String> VALID_STATUSES = Set.of(
            "UNASSIGNED", "OPEN", "ACKNOWLEDGED", "LINKED_TO_INCIDENT", "RESOLVED", "DISMISSED"
    );

    private final OpenSearchFindingAdapter findingAdapter;

    public FindingService(OpenSearchFindingAdapter findingAdapter) {
        this.findingAdapter = findingAdapter;
    }

    public List<FindingDto> getAllFindings() {
        return findingAdapter.fetchFindings();
    }

    public Optional<FindingDto> getFindingById(String findingId) {
        return findingAdapter.getFindingById(findingId);
    }

    public List<FindingDto> getFindingsByRule(String ruleCode) {
        return findingAdapter.fetchFindings().stream()
                .filter(f -> ruleCode.equalsIgnoreCase(f.getRuleId()))
                .collect(Collectors.toList());
    }

    public List<FindingDto> getFindingsByAsset(String assetIdentifier) {
        return findingAdapter.fetchFindings().stream()
                .filter(f -> assetIdentifier.equalsIgnoreCase(f.getAssetId()) || assetIdentifier.equalsIgnoreCase(f.getAssetName()))
                .collect(Collectors.toList());
    }

    public List<FindingDto> searchFindings(String severity, String ruleId, String status, String assetId, int limit) {
        int safeLimit = limit <= 0 ? 50 : Math.min(limit, 200);
        return findingAdapter.fetchFindings().stream()
                .filter(f -> severity == null || severity.equalsIgnoreCase(f.getRuleSeverity()))
                .filter(f -> ruleId == null || ruleId.equalsIgnoreCase(f.getRuleId()))
                .filter(f -> status == null || status.equalsIgnoreCase(f.getStatus()))
                .filter(f -> assetId == null || assetId.equalsIgnoreCase(f.getAssetId()) || assetId.equalsIgnoreCase(f.getAssetName()))
                .limit(safeLimit)
                .collect(Collectors.toList());
    }

    public FindingDto updateFindingStatus(String findingId, String status) {
        if (status == null || status.isBlank()) {
            throw new InvalidActionException("Finding status cannot be empty.");
        }
        String cleanStatus = status.trim().toUpperCase(Locale.ROOT);
        if (!VALID_STATUSES.contains(cleanStatus)) {
            throw new InvalidActionException("Invalid finding status: " + status + ". Allowed: " + VALID_STATUSES);
        }

        FindingDto finding = findingAdapter.getFindingById(findingId)
                .orElseThrow(() -> new ResourceNotFoundException("Finding", "id", findingId));

        finding.setStatus(cleanStatus);
        findingAdapter.registerFinding(finding);
        return finding;
    }

    public List<RelatedFindingDto> getRelatedFindings(String findingId) {
        FindingDto target = findingAdapter.getFindingById(findingId)
                .orElseThrow(() -> new ResourceNotFoundException("Finding", "id", findingId));

        List<RelatedFindingDto> related = new ArrayList<>();
        List<FindingDto> allFindings = findingAdapter.fetchFindings();

        for (FindingDto other : allFindings) {
            if (other.getFindingId() == null || other.getFindingId().equalsIgnoreCase(findingId)) {
                continue;
            }

            // 1. Shared Asset
            boolean sameAsset = (target.getAssetId() != null && target.getAssetId().equalsIgnoreCase(other.getAssetId()))
                    || (target.getAssetName() != null && target.getAssetName().equalsIgnoreCase(other.getAssetName()));

            if (sameAsset) {
                related.add(new RelatedFindingDto(
                        other, "SHARED_ASSET",
                        "Correlated detection on common host entity: " + target.getAssetName(), 0.90
                ));
                continue;
            }

            // 2. Shared Source IP
            String targetIp = extractIpFromDetails(target);
            String otherIp = extractIpFromDetails(other);
            if (targetIp != null && targetIp.equals(otherIp)) {
                related.add(new RelatedFindingDto(
                        other, "SHARED_SOURCE_IP",
                        "Correlated adversary source IP: " + targetIp, 0.85
                ));
                continue;
            }

            // 3. Shared MITRE Tactic
            if (target.getMitreTactic() != null && target.getMitreTactic().equalsIgnoreCase(other.getMitreTactic())) {
                related.add(new RelatedFindingDto(
                        other, "SHARED_TACTIC",
                        "Common attack campaign phase (MITRE " + target.getMitreTactic() + ")", 0.70
                ));
                continue;
            }

            // 4. Same Rule
            if (target.getRuleId() != null && target.getRuleId().equalsIgnoreCase(other.getRuleId())) {
                related.add(new RelatedFindingDto(
                        other, "SAME_RULE",
                        "Recurrent activation of detection rule: " + target.getRuleId(), 0.75
                ));
            }
        }

        related.sort(Comparator.comparingDouble(RelatedFindingDto::getConfidenceScore).reversed());
        return related;
    }

    private String extractIpFromDetails(FindingDto f) {
        if (f.getDetails() == null) return null;
        Object srcIp = f.getDetails().get("src_ip");
        if (srcIp != null) return srcIp.toString();
        Object sourceIp = f.getDetails().get("source_ip");
        if (sourceIp != null) return sourceIp.toString();
        return null;
    }
}

