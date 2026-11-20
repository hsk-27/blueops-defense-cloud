package com.blueops.detections.sigma;

import com.blueops.telemetry.NormalizedEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SigmaFieldMatcherTest {

    private final SigmaFieldMatcher matcher = new SigmaFieldMatcher();

    @Test
    @DisplayName("Should match contains modifier with single value and list of values")
    void testContainsModifier() {
        NormalizedEvent event = new NormalizedEvent();
        event.setProcess(new NormalizedEvent.ProcessMetadata(
                1234L, "powershell.exe", "C:\\Windows\\System32\\powershell.exe",
                "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA...", null, null
        ));

        // Single value contains match
        Map<String, Object> criteria1 = Map.of(
                "CommandLine|contains", "-enc"
        );
        assertTrue(matcher.matchesSelection(criteria1, event));

        // List of values contains match (OR semantics)
        Map<String, Object> criteria2 = Map.of(
                "CommandLine|contains", List.of("-EncodedCommand", "-enc", "-ep bypass")
        );
        assertTrue(matcher.matchesSelection(criteria2, event));

        // Negative match
        Map<String, Object> criteria3 = Map.of(
                "CommandLine|contains", "DownloadString"
        );
        assertFalse(matcher.matchesSelection(criteria3, event));
    }

    @Test
    @DisplayName("Should match endswith modifier with normalized path slashes")
    void testEndswithModifier() {
        NormalizedEvent event = new NormalizedEvent();
        event.setProcess(new NormalizedEvent.ProcessMetadata(
                4567L, "cmd.exe", "C:\\Windows\\System32\\cmd.exe",
                "cmd.exe /c whoami", null, null
        ));

        Map<String, Object> criteria = Map.of(
                "Image|endswith", List.of("\\powershell.exe", "\\cmd.exe")
        );
        assertTrue(matcher.matchesSelection(criteria, event));

        Map<String, Object> negativeCriteria = Map.of(
                "Image|endswith", "\\winword.exe"
        );
        assertFalse(matcher.matchesSelection(negativeCriteria, event));
    }

    @Test
    @DisplayName("Should match startswith modifier")
    void testStartswithModifier() {
        NormalizedEvent event = new NormalizedEvent();
        event.setFile(new NormalizedEvent.FileMetadata(
                "/etc/systemd/system/malicious.service", "malicious.service", 1024L, "hash"
        ));

        Map<String, Object> criteria = Map.of(
                "file.path|startswith", "/etc/systemd/system"
        );
        assertTrue(matcher.matchesSelection(criteria, event));
    }

    @Test
    @DisplayName("Should support wildcard matching in values (* and ?)")
    void testWildcardMatch() {
        NormalizedEvent event = new NormalizedEvent();
        event.setProcess(new NormalizedEvent.ProcessMetadata(
                7890L, "rundll32.exe", "C:\\Windows\\System32\\rundll32.exe",
                "rundll32.exe C:\\windows\\System32\\comsvcs.dll, #24 672 C:\\temp\\lsass.dmp full", null, null
        ));

        Map<String, Object> criteria = Map.of(
                "CommandLine|contains", "*comsvcs*MiniDump*"
        );
        // Fallback or exact glob pattern
        assertTrue(SigmaFieldMatcher.wildcardMatch(event.getProcess().getCommandLine(), "*comsvcs*lsass.dmp*"));
    }
}
