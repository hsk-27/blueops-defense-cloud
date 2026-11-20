package com.blueops.detections.sigma;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class SigmaRuleParserAndRegistryTest {

    private final SigmaRuleParser parser = new SigmaRuleParser();

    @Test
    @DisplayName("Should successfully parse a raw Sigma YAML string into strongly typed SigmaRuleDefinition")
    void testParseRawYaml() {
        String yaml = """
            title: Suspicious PowerShell Encoded Execution
            id: 5f1b1e90-0008-4e89-9a08-000000000008
            status: test
            description: Detects encoded PowerShell execution flags.
            references:
                - https://attack.mitre.org/techniques/T1059/001/
            author: BlueOps Detection Engineering
            date: 2026-11-01
            tags:
                - attack.execution
                - attack.t1059.001
            logsource:
                category: process_creation
                product: windows
                service: sysmon
            detection:
                selection:
                    CommandLine|contains:
                        - ' -enc '
                        - ' -EncodedCommand '
                condition: selection
            level: high
            """;

        SigmaRuleDefinition rule = parser.parse(yaml, "D008_suspicious_powershell.yml");

        assertNotNull(rule);
        assertEquals("D008", rule.getRuleCode());
        assertEquals("Suspicious PowerShell Encoded Execution", rule.getTitle());
        assertEquals("HIGH", rule.getLevel());
        assertEquals("T1059.001", rule.getMitreTechniqueId());
        assertEquals("Execution", rule.getMitreTactic());
        assertEquals("windows", rule.getLogsource().get("product"));
        assertNotNull(rule.getDetection());
    }

    @Test
    @DisplayName("Should load and register all 18 real Sigma YAML rule files from project storage")
    void testRegistryLoadsAllRealRules() {
        SigmaRuleRegistry registry = new SigmaRuleRegistry(parser, "");
        int loaded = registry.reloadRules();

        assertTrue(loaded >= 18, "Registry should load at least 18 Sigma rules. Actual: " + loaded);

        // Verify specific rules
        Optional<SigmaRuleDefinition> d001 = registry.getRuleByCode("D001");
        assertTrue(d001.isPresent(), "D001 should be loaded");
        assertEquals("Repeated SSH Authentication Failures", d001.get().getTitle());
        assertEquals("T1110.001", d001.get().getMitreTechniqueId());

        Optional<SigmaRuleDefinition> d008 = registry.getRuleByCode("D008");
        assertTrue(d008.isPresent(), "D008 should be loaded");
        assertEquals("Suspicious PowerShell Execution", d008.get().getTitle());
        assertEquals("T1059.001", d008.get().getMitreTechniqueId());

        Optional<SigmaRuleDefinition> d011 = registry.getRuleByCode("D011");
        assertTrue(d011.isPresent(), "D011 should be loaded");
        assertTrue(d011.get().getTitle().contains("LSASS"));

        Optional<SigmaRuleDefinition> d015 = registry.getRuleByCode("D015");
        assertTrue(d015.isPresent(), "D015 should be loaded");
        assertTrue(d015.get().getTitle().contains("Threat Intelligence"));

        // Verify logsource filtering
        List<SigmaRuleDefinition> windowsRules = registry.getRulesByLogSourceProduct("windows");
        assertFalse(windowsRules.isEmpty());
        assertTrue(windowsRules.stream().anyMatch(r -> "D008".equals(r.getRuleCode())));

        List<SigmaRuleDefinition> linuxRules = registry.getRulesByLogSourceProduct("linux");
        assertFalse(linuxRules.isEmpty());
        assertTrue(linuxRules.stream().anyMatch(r -> "D001".equals(r.getRuleCode())));
    }

    @Test
    @DisplayName("Should support concurrent lock-free queries during rule reload without race window (SEC-003)")
    void testConcurrentQueriesDuringReload() throws Exception {
        SigmaRuleRegistry registry = new SigmaRuleRegistry(parser, "");
        int initialLoaded = registry.reloadRules();
        assertTrue(initialLoaded >= 18);

        int readerThreads = 8;
        ExecutorService executor = Executors.newFixedThreadPool(readerThreads + 1);
        AtomicInteger successfulReads = new AtomicInteger(0);
        AtomicInteger emptyReads = new AtomicInteger(0);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(readerThreads);

        // Reader tasks continuously querying rules
        for (int i = 0; i < readerThreads; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < 500; j++) {
                        Optional<SigmaRuleDefinition> rule = registry.getRuleByCode("D008");
                        if (rule.isPresent() && "D008".equals(rule.get().getRuleCode())) {
                            successfulReads.incrementAndGet();
                        } else {
                            emptyReads.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    finishLatch.countDown();
                }
            });
        }

        // Trigger start and immediately reload rules concurrently
        startLatch.countDown();
        Future<Integer> reloadFuture = executor.submit(registry::reloadRules);

        assertTrue(finishLatch.await(5, TimeUnit.SECONDS), "Reader threads should finish within 5s");
        int reloadedCount = reloadFuture.get(5, TimeUnit.SECONDS);

        executor.shutdown();
        assertTrue(reloadedCount >= 18);
        assertTrue(successfulReads.get() > 0, "Readers should have executed successfully");
        assertEquals(0, emptyReads.get(), "Zero empty reads should occur during concurrent reload (atomic reference swap)");
    }
}
