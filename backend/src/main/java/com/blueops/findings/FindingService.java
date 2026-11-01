package com.blueops.findings;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class FindingService {

    private final OpenSearchFindingAdapter findingAdapter;

    public FindingService(OpenSearchFindingAdapter findingAdapter) {
        this.findingAdapter = findingAdapter;
    }

    public List<FindingDto> getAllFindings() {
        return findingAdapter.fetchFindings();
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
}
