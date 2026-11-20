package com.blueops.incidents;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.audit.AuditLog;
import com.blueops.audit.AuditService;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import com.blueops.findings.FindingDto;
import com.blueops.findings.FindingService;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.findings.RelatedFindingDto;
import com.blueops.telemetry.EventNormalizationService;
import com.blueops.telemetry.NormalizedEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.data.domain.*;
import org.springframework.data.repository.query.FluentQuery;

import java.time.Instant;
import java.util.*;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Incident Lifecycle and Analyst Workflow Unit Test Suite (M4).
 * Rigorously verifies lifecycle state machine, assignment, notes, finding associations,
 * related findings engine, evidence model, and audit integrity.
 */
class IncidentLifecycleAndWorkflowTest {

    private IncidentService incidentService;
    private FindingService findingService;
    private EventNormalizationService normalizationService;
    private OpenSearchFindingAdapter findingAdapter;

    private Map<Long, Incident> incidentStore;
    private List<FindingDto> adapterFindings;
    private List<AuditRecord> auditRecords;

    private static record AuditRecord(String actor, String action, String entityType, String entityId, String details) {}

    @BeforeEach
    void setUp() {
        incidentStore = new HashMap<>();
        adapterFindings = new ArrayList<>();
        auditRecords = new ArrayList<>();

        findingAdapter = new OpenSearchFindingAdapter(
                new RestTemplateBuilder(), "http://localhost:9200", "admin", "admin", false
        ) {
            @Override
            public void registerFinding(FindingDto finding) {
                adapterFindings.removeIf(f -> f.getFindingId().equalsIgnoreCase(finding.getFindingId()));
                adapterFindings.add(finding);
            }

            @Override
            public List<FindingDto> fetchFindings() {
                return new ArrayList<>(adapterFindings);
            }

            @Override
            public Optional<FindingDto> getFindingById(String findingId) {
                return adapterFindings.stream()
                        .filter(f -> f.getFindingId().equalsIgnoreCase(findingId))
                        .findFirst();
            }
        };

        findingService = new FindingService(findingAdapter);
        normalizationService = new EventNormalizationService();

        AuditService auditService = new AuditService(null) {
            @Override
            public void recordEvent(String actor, String action, String entityType, String entityId, String clientIp, String details) {
                auditRecords.add(new AuditRecord(actor, action, entityType, entityId, details));
            }
        };

        Asset mockAsset = new Asset();
        mockAsset.setId(10L);
        mockAsset.setPersistentId("WIN-ASSET-001");
        mockAsset.setHostname("WIN-WORKSTATION-01");
        mockAsset.setIpAddress("192.168.56.101");

        AssetRepository assetRepository = new StubAssetRepository(mockAsset);
        IncidentRepository incidentRepository = new StubIncidentRepository(incidentStore);

        incidentService = new IncidentService(
                incidentRepository, assetRepository, findingAdapter, auditService, normalizationService
        );
    }

    @Test
    @DisplayName("Lifecycle: Valid state machine transition sequence (NEW -> TRIAGED -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED)")
    void testCompleteValidLifecycleTransitions() {
        IncidentCreateRequest createReq = new IncidentCreateRequest();
        createReq.setTitle("Active C2 Communication Beacon");
        createReq.setSeverity(IncidentSeverity.HIGH);
        createReq.setPriority(IncidentPriority.P2_HIGH);

        IncidentDto incident = incidentService.createIncident(createReq, "analyst.alice");
        assertEquals("NEW", incident.getStatus());
        assertEquals("P2_HIGH", incident.getPriority());

        // 1. NEW -> TRIAGED
        IncidentStatusUpdateRequest triageReq = new IncidentStatusUpdateRequest();
        triageReq.setStatus(IncidentStatus.TRIAGED);
        triageReq.setReason("Initial triage completed; high fidelity beacon verified");
        incident = incidentService.updateStatus(incident.getId(), triageReq, "analyst.alice");
        assertEquals("TRIAGED", incident.getStatus());

        // 2. TRIAGED -> INVESTIGATING
        IncidentStatusUpdateRequest invReq = new IncidentStatusUpdateRequest();
        invReq.setStatus(IncidentStatus.INVESTIGATING);
        invReq.setReason("Deep packet inspection and host memory dump requested");
        incident = incidentService.updateStatus(incident.getId(), invReq, "analyst.bob");
        assertEquals("INVESTIGATING", incident.getStatus());

        // 3. INVESTIGATING -> CONTAINED
        IncidentStatusUpdateRequest contReq = new IncidentStatusUpdateRequest();
        contReq.setStatus(IncidentStatus.CONTAINED);
        contReq.setReason("Host isolated on perimeter firewall");
        incident = incidentService.updateStatus(incident.getId(), contReq, "analyst.bob");
        assertEquals("CONTAINED", incident.getStatus());
        assertNotNull(incident.getContainedAt());

        // 4. CONTAINED -> RESOLVED (Requires rationale)
        IncidentStatusUpdateRequest resolveReq = new IncidentStatusUpdateRequest();
        resolveReq.setStatus(IncidentStatus.RESOLVED);
        resolveReq.setResolutionRationale("Adversary C2 process terminated and persistence registry keys deleted");
        incident = incidentService.updateStatus(incident.getId(), resolveReq, "analyst.bob");
        assertEquals("RESOLVED", incident.getStatus());
        assertNotNull(incident.getResolvedAt());
        assertEquals("Adversary C2 process terminated and persistence registry keys deleted", incident.getResolutionRationale());

        // 5. RESOLVED -> CLOSED (Deliberate post-investigation review)
        IncidentStatusUpdateRequest closeReq = new IncidentStatusUpdateRequest();
        closeReq.setStatus(IncidentStatus.CLOSED);
        closeReq.setClosureNotes("Formal SOC sign-off complete. Perimeter rules verified.");
        incident = incidentService.updateStatus(incident.getId(), closeReq, "soc.lead");
        assertEquals("CLOSED", incident.getStatus());
        assertNotNull(incident.getClosedAt());
        assertEquals("soc.lead", incident.getClosedBy());
        assertEquals("Formal SOC sign-off complete. Perimeter rules verified.", incident.getClosureNotes());

        // 6. CLOSED -> REOPENED
        IncidentDto reopened = incidentService.reopenIncident(incident.getId(), "Secondary beacon detected from dormant scheduled task", "threat.hunter");
        assertEquals("REOPENED", reopened.getStatus());

        // Verify full timeline contains all chronological milestones
        List<IncidentTimelineEntryDto> timeline = incidentService.getTimeline(incident.getId());
        assertTrue(timeline.size() >= 7, "Timeline must capture all lifecycle transitions and closure");
        assertEquals("STATUS_CHANGE", timeline.get(0).getType());
    }

    @Test
    @DisplayName("Lifecycle: Invalid state machine transitions are rejected with InvalidActionException")
    void testInvalidTransitionsRejected() {
        IncidentCreateRequest createReq = new IncidentCreateRequest();
        createReq.setTitle("Unauthorized Kerberos Request");
        createReq.setSeverity(IncidentSeverity.MEDIUM);

        IncidentDto incident = incidentService.createIncident(createReq, "analyst.alice");

        // Attempt NEW -> RESOLVED directly without investigation
        IncidentStatusUpdateRequest directResolveReq = new IncidentStatusUpdateRequest();
        directResolveReq.setStatus(IncidentStatus.RESOLVED);
        directResolveReq.setResolutionRationale("Quick close");

        assertThrows(InvalidActionException.class, () ->
                incidentService.updateStatus(incident.getId(), directResolveReq, "analyst.alice")
        );

        // Attempt NEW -> CLOSED directly
        IncidentStatusUpdateRequest directCloseReq = new IncidentStatusUpdateRequest();
        directCloseReq.setStatus(IncidentStatus.CLOSED);
        assertThrows(InvalidActionException.class, () ->
                incidentService.updateStatus(incident.getId(), directCloseReq, "analyst.alice")
        );
    }

    @Test
    @DisplayName("Lifecycle: Resolving an incident requires a non-blank resolution rationale")
    void testResolutionRationaleRequired() {
        IncidentCreateRequest createReq = new IncidentCreateRequest();
        createReq.setTitle("Malicious Script Execution");
        createReq.setSeverity(IncidentSeverity.HIGH);
        IncidentDto incident = incidentService.createIncident(createReq, "analyst.alice");

        // Move to INVESTIGATING
        IncidentStatusUpdateRequest invReq = new IncidentStatusUpdateRequest();
        invReq.setStatus(IncidentStatus.INVESTIGATING);
        incidentService.updateStatus(incident.getId(), invReq, "analyst.alice");

        // Attempt to RESOLVE with empty rationale
        IncidentStatusUpdateRequest emptyRationaleReq = new IncidentStatusUpdateRequest();
        emptyRationaleReq.setStatus(IncidentStatus.RESOLVED);
        emptyRationaleReq.setResolutionRationale("   ");

        assertThrows(InvalidActionException.class, () ->
                incidentService.updateStatus(incident.getId(), emptyRationaleReq, "analyst.alice")
        );
    }

    @Test
    @DisplayName("Assignment: Analyst assignment, reassignment, and unassignment are audited and tracked")
    void testAnalystAssignmentWorkflow() {
        IncidentCreateRequest createReq = new IncidentCreateRequest();
        createReq.setTitle("Suspected Credential Dumping");
        createReq.setSeverity(IncidentSeverity.CRITICAL);
        IncidentDto incident = incidentService.createIncident(createReq, "soc.dispatcher");

        assertNull(incident.getAssignedTo());

        // 1. Assign to analyst
        IncidentAssignRequest assignAlice = new IncidentAssignRequest();
        assignAlice.setAssignedTo("analyst.alice");
        IncidentDto updated1 = incidentService.assignIncident(incident.getId(), assignAlice, "soc.dispatcher");
        assertEquals("analyst.alice", updated1.getAssignedTo());

        // 2. Reassign to specialist
        IncidentAssignRequest assignBob = new IncidentAssignRequest();
        assignBob.setAssignedTo("specialist.bob");
        IncidentDto updated2 = incidentService.assignIncident(incident.getId(), assignBob, "analyst.alice");
        assertEquals("specialist.bob", updated2.getAssignedTo());

        // 3. Unassign
        IncidentAssignRequest unassign = new IncidentAssignRequest();
        unassign.setAssignedTo("unassigned");
        IncidentDto updated3 = incidentService.assignIncident(incident.getId(), unassign, "soc.dispatcher");
        assertNull(updated3.getAssignedTo());

        // Verify audit records
        assertTrue(auditRecords.stream().anyMatch(a -> "INCIDENT_ASSIGNED".equals(a.action()) && a.details().contains("analyst.alice")));
        assertTrue(auditRecords.stream().anyMatch(a -> "INCIDENT_ASSIGNED".equals(a.action()) && a.details().contains("specialist.bob")));
    }

    @Test
    @DisplayName("Notes: Analyst notes are validated, appended, and preserved in incident timeline")
    void testAnalystNotesWorkflow() {
        IncidentCreateRequest createReq = new IncidentCreateRequest();
        createReq.setTitle("Investigation with Evidence Notes");
        createReq.setSeverity(IncidentSeverity.MEDIUM);
        IncidentDto incident = incidentService.createIncident(createReq, "analyst.alice");

        // Reject blank note
        IncidentNoteRequest blankNote = new IncidentNoteRequest();
        blankNote.setNoteText("   \n  ");
        assertThrows(InvalidActionException.class, () ->
                incidentService.addNote(incident.getId(), blankNote, "analyst.alice")
        );

        // Append valid note
        IncidentNoteRequest validNote = new IncidentNoteRequest();
        validNote.setNoteText("Pivoted on source IP 198.51.100.99; associated with known APT staging infrastructure.");
        incidentService.addNote(incident.getId(), validNote, "analyst.alice");

        List<IncidentTimelineEntryDto> timeline = incidentService.getTimeline(incident.getId());
        assertTrue(timeline.stream().anyMatch(t -> "NOTE".equals(t.getType()) && t.getDescription().contains("198.51.100.99")));

        assertTrue(auditRecords.stream().anyMatch(a -> "INCIDENT_NOTE_ADDED".equals(a.action())));
    }

    @Test
    @DisplayName("Findings: Attaching and detaching findings synchronizes finding status and preserves relationships")
    void testFindingAssociationAndDetachment() {
        // Register mock finding in adapter
        FindingDto finding1 = new FindingDto(
                "FND-2026-001", "D008", "Suspicious Encoded PowerShell", "HIGH",
                "Execution", "T1059.001", "PowerShell", "WIN-ASSET-001", "WIN-WORKSTATION-01",
                Instant.now(), "OPEN", "DOC-RAW-001", Map.of("cmd", "powershell -enc ...")
        );
        findingAdapter.registerFinding(finding1);

        IncidentCreateRequest createReq = new IncidentCreateRequest();
        createReq.setTitle("PowerShell Attack Investigation");
        createReq.setSeverity(IncidentSeverity.HIGH);
        createReq.setFindingIds(List.of("FND-2026-001"));

        IncidentDto incident = incidentService.createIncident(createReq, "analyst.alice");
        assertEquals(1, incident.getFindingCount());

        // Verify finding status was updated to LINKED_TO_INCIDENT
        assertEquals("LINKED_TO_INCIDENT", findingAdapter.getFindingById("FND-2026-001").get().getStatus());

        // Prevent duplicate attachment
        assertThrows(InvalidActionException.class, () ->
                incidentService.attachFinding(incident.getId(), "FND-2026-001", "analyst.alice")
        );

        // Detach finding
        incidentService.detachFinding(incident.getId(), "FND-2026-001", "analyst.alice");
        assertEquals("OPEN", findingAdapter.getFindingById("FND-2026-001").get().getStatus());

        List<IncidentFinding> remaining = incidentService.getIncidentFindings(incident.getId());
        assertTrue(remaining.isEmpty());
    }

    @Test
    @DisplayName("Related Findings: Engine correlates findings by shared asset, IP, tactic, and rule")
    void testRelatedFindingsEngine() {
        FindingDto primary = new FindingDto(
                "FND-TARGET", "D008", "PowerShell Download Cradle", "HIGH",
                "Execution", "T1059.001", "PowerShell", "WIN-ASSET-001", "WIN-WORKSTATION-01",
                Instant.now(), "OPEN", "DOC-1", Map.of("src_ip", "203.0.113.50")
        );
        FindingDto onSameAsset = new FindingDto(
                "FND-ASSET-MATCH", "D011", "LSASS Memory Dump", "CRITICAL",
                "Credential Access", "T1003.001", "LSASS", "WIN-ASSET-001", "WIN-WORKSTATION-01",
                Instant.now(), "OPEN", "DOC-2", Map.of("src_ip", "10.0.0.1")
        );
        FindingDto onSameIp = new FindingDto(
                "FND-IP-MATCH", "D015", "C2 Beacon", "HIGH",
                "Command and Control", "T1071.001", "Network", "WIN-ASSET-999", "SRV-REMOTE",
                Instant.now(), "OPEN", "DOC-3", Map.of("src_ip", "203.0.113.50")
        );
        FindingDto sameTactic = new FindingDto(
                "FND-TACTIC-MATCH", "D009", "Office Spawning CMD", "HIGH",
                "Execution", "T1059.003", "Cmd", "WIN-ASSET-777", "DESKTOP-HR",
                Instant.now(), "OPEN", "DOC-4", Map.of()
        );

        findingAdapter.registerFinding(primary);
        findingAdapter.registerFinding(onSameAsset);
        findingAdapter.registerFinding(onSameIp);
        findingAdapter.registerFinding(sameTactic);

        List<RelatedFindingDto> related = findingService.getRelatedFindings("FND-TARGET");
        assertEquals(3, related.size());

        // Verify SHARED_ASSET correlation
        assertTrue(related.stream().anyMatch(r -> "SHARED_ASSET".equals(r.getRelationType()) && r.getFinding().getFindingId().equals("FND-ASSET-MATCH")));
        // Verify SHARED_SOURCE_IP correlation
        assertTrue(related.stream().anyMatch(r -> "SHARED_SOURCE_IP".equals(r.getRelationType()) && r.getFinding().getFindingId().equals("FND-IP-MATCH")));
        // Verify SHARED_TACTIC correlation
        assertTrue(related.stream().anyMatch(r -> "SHARED_TACTIC".equals(r.getRelationType()) && r.getFinding().getFindingId().equals("FND-TACTIC-MATCH")));
    }

    @Test
    @DisplayName("Evidence Model: Aggregated incident evidence links back to raw event provenance without data loss")
    void testIncidentEvidenceRetrieval() {
        // Ingest telemetry into EventNormalizationService
        Map<String, Object> raw = new HashMap<>();
        raw.put("id", "evt-evd-001");
        raw.put("provider", "Sysmon");
        raw.put("hostname", "WIN-WORKSTATION-01");
        raw.put("host_ip", "192.168.56.101");
        raw.put("src_ip", "198.51.100.33");
        raw.put("username", "analyst.dev");
        raw.put("Image", "C:\\Windows\\System32\\cmd.exe");
        raw.put("CommandLine", "cmd.exe /c whoami /all");
        NormalizedEvent event = normalizationService.normalize(raw);

        // Register finding linked to this event doc ID
        FindingDto finding = new FindingDto(
                "FND-EVD-99", "D009", "Command Interpreter Spawning", "MEDIUM",
                "Execution", "T1059.003", "Sysmon", "WIN-ASSET-001", "WIN-WORKSTATION-01",
                Instant.now(), "OPEN", "evt-evd-001", Map.of("cmd", "cmd.exe /c whoami /all")
        );
        findingAdapter.registerFinding(finding);

        // Create incident linked to finding
        IncidentCreateRequest req = new IncidentCreateRequest();
        req.setTitle("Reconnaissance on Workstation");
        req.setSeverity(IncidentSeverity.MEDIUM);
        req.setFindingIds(List.of("FND-EVD-99"));
        IncidentDto inc = incidentService.createIncident(req, "analyst.alice");

        // Retrieve Evidence
        List<IncidentEvidenceDto> evidence = incidentService.getIncidentEvidence(inc.getId());
        assertEquals(1, evidence.size());

        IncidentEvidenceDto item = evidence.get(0);
        assertEquals("FND-EVD-99", item.getFindingId());
        assertEquals("D009", item.getRuleId());
        assertEquals("Sysmon", item.getProvider());
        assertEquals("WIN-WORKSTATION-01", item.getHost());
        assertEquals("198.51.100.33", item.getSourceIp());
        assertEquals("cmd.exe /c whoami /all", item.getProcess());
        assertNotNull(item.getRawPayload(), "Raw payload must be preserved");
        assertTrue(item.getRawPayload().contains("whoami /all"));
    }

    // --- Repositories Test Doubles ---

    private static class StubIncidentRepository implements IncidentRepository {
        private final Map<Long, Incident> store;
        private long idGen = 1L;

        StubIncidentRepository(Map<Long, Incident> store) {
            this.store = store;
        }

        @Override
        public <S extends Incident> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(idGen++);
            }
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override public Optional<Incident> findById(Long id) { return Optional.ofNullable(store.get(id)); }
        @Override public Optional<Incident> findByIncidentNumber(String incidentNumber) { return Optional.empty(); }
        @Override public List<Incident> findByStatus(IncidentStatus status) { return store.values().stream().filter(i -> i.getStatus() == status).toList(); }
        @Override public Page<Incident> findByStatus(IncidentStatus status, Pageable pageable) { return Page.empty(); }
        @Override public long countByStatus(IncidentStatus status) { return store.values().stream().filter(i -> i.getStatus() == status).count(); }
        @Override public long countBySeverity(IncidentSeverity severity) { return 0; }
        @Override public Page<Incident> findFiltered(IncidentStatus status, IncidentSeverity severity, Pageable pageable) { return Page.empty(); }
        @Override public Page<Incident> findFilteredAdvanced(IncidentStatus status, IncidentSeverity severity, IncidentPriority priority, String assignedTo, String query, Pageable pageable) { return Page.empty(); }
        @Override public long countActiveIncidents() { return 0; }
        @Override public List<Incident> findActiveByTitleAndAsset(String title, Long assetId) { return List.of(); }
        @Override public long countAssetsWithActiveIncidents() { return 0; }
        @Override public List<Incident> findTop5ByOrderByCreatedAtDesc() { return List.of(); }
        @Override public List<Incident> findByContainedAtIsNotNullAndCreatedAtIsNotNull() { return List.of(); }
        @Override public List<Incident> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<Incident> findAll(Sort sort) { return List.of(); }
        @Override public List<Incident> findAllById(Iterable<Long> longs) { return List.of(); }
        @Override public <S extends Incident> List<S> saveAll(Iterable<S> entities) { return List.of(); }
        @Override public void flush() {}
        @Override public <S extends Incident> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends Incident> List<S> saveAllAndFlush(Iterable<S> entities) { return List.of(); }
        @Override public void deleteAllInBatch(Iterable<Incident> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public Incident getOne(Long aLong) { return null; }
        @Override public Incident getById(Long aLong) { return null; }
        @Override public Incident getReferenceById(Long aLong) { return null; }
        @Override public <S extends Incident> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends Incident> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends Incident> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends Incident> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends Incident> long count(Example<S> example) { return 0; }
        @Override public <S extends Incident> boolean exists(Example<S> example) { return false; }
        @Override public <S extends Incident, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(Incident entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends Incident> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public Page<Incident> findAll(Pageable pageable) { return Page.empty(); }
    }

    private static class StubAssetRepository implements AssetRepository {
        private final Asset asset;
        StubAssetRepository(Asset asset) { this.asset = asset; }
        @Override public Optional<Asset> findByPersistentId(String id) { return Optional.of(asset); }
        @Override public Optional<Asset> findByHostname(String host) { return Optional.of(asset); }
        @Override public Optional<Asset> findByHostnameIgnoreCase(String host) { return Optional.of(asset); }
        @Override public Optional<Asset> findByIpAddress(String ip) { return Optional.of(asset); }
        @Override public boolean existsByPersistentId(String id) { return true; }
        @Override public <S extends Asset> S save(S entity) { return entity; }
        @Override public <S extends Asset> List<S> saveAll(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public Optional<Asset> findById(Long aLong) { return Optional.of(asset); }
        @Override public boolean existsById(Long aLong) { return true; }
        @Override public List<Asset> findAll() { return List.of(asset); }
        @Override public List<Asset> findAllById(Iterable<Long> longs) { return List.of(asset); }
        @Override public long count() { return 1; }
        @Override public void deleteById(Long aLong) {}
        @Override public void delete(Asset entity) {}
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends Asset> entities) {}
        @Override public void deleteAll() {}
        @Override public void flush() {}
        @Override public <S extends Asset> S saveAndFlush(S entity) { return entity; }
        @Override public <S extends Asset> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<Asset> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public Asset getOne(Long aLong) { return asset; }
        @Override public Asset getById(Long aLong) { return asset; }
        @Override public Asset getReferenceById(Long aLong) { return asset; }
        @Override public <S extends Asset> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends Asset> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends Asset> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends Asset> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends Asset> long count(Example<S> example) { return 0; }
        @Override public <S extends Asset> boolean exists(Example<S> example) { return false; }
        @Override public <S extends Asset, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<Asset> findAll(Sort sort) { return List.of(asset); }
        @Override public Page<Asset> findAll(Pageable pageable) { return Page.empty(); }
    }
}
