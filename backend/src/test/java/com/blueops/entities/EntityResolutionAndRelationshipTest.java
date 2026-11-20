package com.blueops.entities;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EntityResolutionAndRelationshipTest {

    private M5TestStubs.StubEntityRepository entityRepository;
    private M5TestStubs.StubEntityObservationRepository observationRepository;
    private M5TestStubs.StubEntityRelationshipRepository relationshipRepository;
    private EntityResolutionService resolutionService;

    @BeforeEach
    void setUp() {
        entityRepository = new M5TestStubs.StubEntityRepository();
        observationRepository = new M5TestStubs.StubEntityObservationRepository();
        relationshipRepository = new M5TestStubs.StubEntityRelationshipRepository();
        ObjectMapper objectMapper = new ObjectMapper();

        resolutionService = new EntityResolutionService(entityRepository, observationRepository, relationshipRepository, objectMapper);
    }

    @Test
    @DisplayName("Canonical Host Normalization resolves FQDN and casing deterministically")
    void testCanonicalHostNormalization() {
        String id1 = resolutionService.buildHostCanonicalId("WIN-PROD-01.corp.internal");
        String id2 = resolutionService.buildHostCanonicalId("win-prod-01");
        String id3 = resolutionService.buildHostCanonicalId("  WIN-PROD-01  ");

        assertEquals("host:win-prod-01", id1);
        assertEquals("host:win-prod-01", id2);
        assertEquals("host:win-prod-01", id3);
    }

    @Test
    @DisplayName("Canonical User Normalization handles domain slashes and casing")
    void testCanonicalUserNormalization() {
        String id1 = resolutionService.buildUserCanonicalId("CORP/Administrator");
        String id2 = resolutionService.buildUserCanonicalId("corp\\administrator");

        assertEquals("user:corp\\administrator", id1);
        assertEquals("user:corp\\administrator", id2);
    }

    @Test
    @DisplayName("Canonical IP and Domain Normalization handles brackets and trailing dots")
    void testCanonicalIpAndDomainNormalization() {
        assertEquals("ip:192.168.1.100", resolutionService.buildIpCanonicalId(" 192.168.1.100 "));
        assertEquals("ip:fe80::1", resolutionService.buildIpCanonicalId("[FE80::1]"));
        assertEquals("domain:evil-c2.org", resolutionService.buildDomainCanonicalId("EVIL-C2.ORG."));
    }

    @Test
    @DisplayName("Canonical Process and File Normalization scopes to host and normalizes separators")
    void testCanonicalProcessAndFileNormalization() {
        String procId = resolutionService.buildProcessCanonicalId("WIN-01.corp", "C:\\Windows\\System32\\powershell.exe", 4104L);
        assertEquals("proc:win-01:powershell.exe:4104", procId);

        String fileId = resolutionService.buildFileCanonicalId("WIN-01", "C:\\Windows\\Temp\\Mimikatz.exe");
        assertEquals("file:win-01:c:/windows/temp/mimikatz.exe", fileId);
    }

    @Test
    @DisplayName("Entity resolution deduplicates observations and increments observation count")
    void testEntityResolutionDeduplication() {
        String canonicalId = "host:srv-linux-01";
        EntityRecord first = resolutionService.resolveOrCreateEntity(EntityType.HOST, canonicalId, "SRV-LINUX-01", Map.of("os", "Ubuntu"), 0.0);
        assertNotNull(first.getId());
        assertEquals(1, first.getObservationCount());

        EntityRecord second = resolutionService.resolveOrCreateEntity(EntityType.HOST, canonicalId, "srv-linux-01", Map.of("env", "PROD"), 10.0);
        assertEquals(first.getId(), second.getId());
        assertEquals(2, second.getObservationCount());
        assertEquals(10.0, second.getRiskScore());
        assertEquals(1, entityRepository.count());
    }

    @Test
    @DisplayName("Risk scoring bounds at 100.0 and transitions entity status to SUSPICIOUS and COMPROMISED")
    void testRiskScoringAndStatusTransitions() {
        String canonicalId = "host:victim-pc";
        EntityRecord e1 = resolutionService.resolveOrCreateEntity(EntityType.HOST, canonicalId, "VICTIM-PC", null, 45.0);
        assertEquals(EntityStatus.SUSPICIOUS, e1.getStatus());

        EntityRecord e2 = resolutionService.resolveOrCreateEntity(EntityType.HOST, canonicalId, "VICTIM-PC", null, 50.0);
        assertEquals(EntityStatus.COMPROMISED, e2.getStatus());
        assertEquals(95.0, e2.getRiskScore());

        EntityRecord e3 = resolutionService.resolveOrCreateEntity(EntityType.HOST, canonicalId, "VICTIM-PC", null, 30.0);
        assertEquals(100.0, e3.getRiskScore(), "Risk score must be capped at 100.0");
    }

    @Test
    @DisplayName("Entity relationships are deduplicated and observation counts incremented")
    void testRelationshipDeduplication() {
        String src = "user:secops";
        String tgt = "host:win-dc-01";

        EntityRelationshipRecord r1 = resolutionService.recordRelationship(
                src, tgt, EntityRelationType.HOST_HAS_USER, 0.9, "Initial logon", "TEST");
        assertNotNull(r1);
        assertEquals(1, r1.getObservationCount());

        EntityRelationshipRecord r2 = resolutionService.recordRelationship(
                src, tgt, EntityRelationType.HOST_HAS_USER, 0.95, "Second logon", "TEST");
        assertEquals(r1.getId(), r2.getId());
        assertEquals(2, r2.getObservationCount());
        assertEquals(0.95, r2.getConfidenceScore());
        assertEquals(1, relationshipRepository.count());
    }

    @Test
    @DisplayName("Self-referential relationships are rejected to avoid loop corruptions")
    void testSelfReferentialRelationshipRejected() {
        EntityRelationshipRecord r = resolutionService.recordRelationship(
                "host:win-dc-01", "host:win-dc-01", EntityRelationType.HOST_HAS_PROCESS, 1.0, "Self loop", "TEST");
        assertNull(r, "Self-loop relationship must be rejected");
        assertEquals(0, relationshipRepository.count());
    }
}
