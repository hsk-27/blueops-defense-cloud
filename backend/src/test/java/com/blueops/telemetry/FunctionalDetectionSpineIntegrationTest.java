package com.blueops.telemetry;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.detections.correlation.CorrelationEngine;
import com.blueops.detections.sigma.*;
import com.blueops.findings.FindingDto;
import com.blueops.findings.FindingService;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.incidents.Incident;
import com.blueops.incidents.IncidentRepository;
import com.blueops.incidents.IncidentService;
import com.blueops.threatintel.IocIndicator;
import com.blueops.threatintel.IocIndicatorRepository;
import com.blueops.threatintel.IocMatch;
import com.blueops.threatintel.IocMatchRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.query.FluentQuery;

import java.time.Instant;
import java.util.*;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Functional Detection Spine Integration Test (M3)
 * Verifies the complete operational lifecycle:
 * TELEMETRY INGESTION -> VALIDATION -> NORMALIZATION -> EVENT STORAGE ->
 * DETECTION EVALUATION -> FINDING GENERATION -> FINDING STORAGE ->
 * INVESTIGATION -> EVIDENCE RETRIEVAL
 */
class FunctionalDetectionSpineIntegrationTest {

    private EventNormalizationService normalizationService;
    private DetectionEvaluationService evaluationService;
    private FindingService findingService;
    private SigmaRuleRegistry sigmaRegistry;
    private SigmaAggregationEngine aggregationEngine;

    private List<FindingDto> registeredFindings;
    private Map<String, IocIndicator> testIocs;

    @BeforeEach
    void setUp() {
        normalizationService = new EventNormalizationService();
        registeredFindings = new ArrayList<>();
        testIocs = new HashMap<>();

        // 1. Thread-safe in-memory adapter test double
        OpenSearchFindingAdapter findingAdapter = new OpenSearchFindingAdapter(
                new RestTemplateBuilder(), "http://localhost:9200", "admin", "admin", false
        ) {
            @Override
            public void registerFinding(FindingDto finding) {
                registeredFindings.add(finding);
                super.registerFinding(finding);
            }

            @Override
            public List<FindingDto> fetchFindings() {
                return new ArrayList<>(registeredFindings);
            }

            @Override
            public Optional<FindingDto> getFindingById(String findingId) {
                return registeredFindings.stream()
                        .filter(f -> f.getFindingId().equalsIgnoreCase(findingId))
                        .findFirst();
            }
        };

        findingService = new FindingService(findingAdapter);

        // 2. Setup Dynamic Sigma Registry & Engine
        SigmaRuleParser parser = new SigmaRuleParser();
        sigmaRegistry = new SigmaRuleRegistry(parser, "");
        sigmaRegistry.reloadRules();

        SigmaFieldMatcher matcher = new SigmaFieldMatcher();
        SigmaConditionEvaluator conditionEvaluator = new SigmaConditionEvaluator();
        aggregationEngine = new SigmaAggregationEngine();
        aggregationEngine.reset();

        SigmaDetectionEvaluator sigmaEvaluator = new SigmaDetectionEvaluator(
                sigmaRegistry, matcher, conditionEvaluator, aggregationEngine
        );

        // 3. Setup repositories
        Asset labAsset = new Asset();
        labAsset.setId(1L);
        labAsset.setPersistentId("WIN-ASSET-001");
        labAsset.setHostname("WIN-WORKSTATION-01");
        labAsset.setIpAddress("192.168.56.101");

        AssetRepository assetRepo = new StubAssetRepository(labAsset);
        IocIndicatorRepository iocRepo = new StubIocIndicatorRepository(testIocs);
        IocMatchRepository matchRepo = new StubIocMatchRepository();
        IncidentRepository incidentRepo = new StubIncidentRepository();
        CorrelationEngine correlationEngine = new CorrelationEngine();

        IncidentService incidentService = new IncidentService(incidentRepo, assetRepo, findingAdapter);

        evaluationService = new DetectionEvaluationService(
                iocRepo, matchRepo, findingAdapter,
                correlationEngine, incidentService, incidentRepo, assetRepo,
                null, sigmaEvaluator
        );
    }

    @Test
    @DisplayName("Stage 1-8: Full Spine - Ingestion -> Normalization -> Detection -> Finding -> Evidence Retrieval")
    void testFullOperationalSpineEndToEnd() {
        // 1. Ingestion: Raw Sysmon Event representing Suspicious PowerShell
        Map<String, Object> rawTelemetry = new HashMap<>();
        String eventId = "evt-spine-" + UUID.randomUUID();
        rawTelemetry.put("id", eventId);
        rawTelemetry.put("provider", "Sysmon");
        rawTelemetry.put("EventID", 1);
        rawTelemetry.put("hostname", "WIN-WORKSTATION-01");
        rawTelemetry.put("host_ip", "192.168.56.101");
        rawTelemetry.put("Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        rawTelemetry.put("CommandLine", "powershell.exe -noni -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp");
        rawTelemetry.put("username", "analyst.dev");

        // 2. Normalization & Validation
        NormalizedEvent event = normalizationService.normalize(rawTelemetry);
        assertNotNull(event, "Event must normalize into CES v1.0.0");
        assertEquals("Sysmon", event.getEvent().getProvider());
        assertEquals("Windows", event.getHost().getOsName());
        assertEquals("powershell.exe", event.getProcess().getName());
        assertNotNull(event.getEvent().getOriginal(), "Provenance must preserve raw input");

        // 3. Event Storage: Event must be retrievable from recent event buffer
        Optional<NormalizedEvent> storedEvent = normalizationService.getEventById(eventId);
        assertTrue(storedEvent.isPresent(), "Event must be retrievable from store");

        // 4. Detection Evaluation
        List<FindingDto> findings = evaluationService.evaluate(event);
        assertFalse(findings.isEmpty(), "Detection engine must generate at least one finding for D008");

        FindingDto d008Finding = findings.stream()
                .filter(f -> "D008".equalsIgnoreCase(f.getRuleId()))
                .findFirst()
                .orElse(null);
        assertNotNull(d008Finding, "Finding for D008 must exist");
        assertEquals("HIGH", d008Finding.getRuleSeverity());
        assertEquals("Execution", d008Finding.getMitreTactic());

        // 5. Finding Persistence & Retrieval
        Optional<FindingDto> retrievedFinding = findingService.getFindingById(d008Finding.getFindingId());
        assertTrue(retrievedFinding.isPresent(), "Finding must be persisted and retrievable via FindingService");

        // 6. Evidence Retrieval: Navigate from Finding -> Triggering Event -> Raw Payload
        String linkedDocId = retrievedFinding.get().getRelatedDocId();
        assertEquals(eventId, linkedDocId, "Finding must link back to originating event ID");

        Optional<NormalizedEvent> evidenceEvent = normalizationService.getEventById(linkedDocId);
        assertTrue(evidenceEvent.isPresent(), "Originating evidence event must be retrievable");
        assertEquals(event.getProcess().getCommandLine(), evidenceEvent.get().getProcess().getCommandLine());
        assertEquals(event.getEvent().getOriginal(), evidenceEvent.get().getEvent().getOriginal());

        // 7. Finding Status Lifecycle: Update status to ACKNOWLEDGED
        FindingDto updatedFinding = findingService.updateFindingStatus(d008Finding.getFindingId(), "ACKNOWLEDGED");
        assertEquals("ACKNOWLEDGED", updatedFinding.getStatus(), "Finding status transition must succeed");
    }

    @Test
    @DisplayName("Negative Scenario: Benign background telemetry traverses full pipeline without generating findings")
    void testBenignTelemetryProducesZeroFindings() {
        Map<String, Object> rawBenign = new HashMap<>();
        rawBenign.put("id", "evt-benign-001");
        rawBenign.put("provider", "Sysmon");
        rawBenign.put("EventID", 1);
        rawBenign.put("hostname", "WIN-WORKSTATION-01");
        rawBenign.put("host_ip", "192.168.56.101");
        rawBenign.put("Image", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
        rawBenign.put("CommandLine", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --no-startup-window");
        rawBenign.put("username", "analyst.dev");

        // Normalization
        NormalizedEvent event = normalizationService.normalize(rawBenign);
        assertNotNull(event);
        assertEquals("chrome.exe", event.getProcess().getName());

        // Detection evaluation
        List<FindingDto> findings = evaluationService.evaluate(event);
        assertTrue(findings.isEmpty(), "Benign event must produce 0 findings (Zero False Positive)");

        // Assert event was stored and retrievable
        assertTrue(normalizationService.getEventById("evt-benign-001").isPresent());
    }

    @Test
    @DisplayName("Aggregation Detection: D001 SSH brute-force triggers only after threshold (>5) within sliding window")
    void testSlidingWindowAggregationD001Lifecycle() {
        String attackerIp = "198.51.100.77";

        // Send 5 failures: count <= 5 -> 0 findings generated
        for (int i = 1; i <= 5; i++) {
            Map<String, Object> rawFail = new HashMap<>();
            rawFail.put("id", "evt-ssh-fail-" + i);
            rawFail.put("provider", "Linux-auditd");
            rawFail.put("action", "ssh_login");
            rawFail.put("outcome", "failure");
            rawFail.put("hostname", "LNX-PROD-SRV-01");
            rawFail.put("host_ip", "192.168.56.102");
            rawFail.put("src_ip", attackerIp);
            rawFail.put("username", "root");

            NormalizedEvent event = normalizationService.normalize(rawFail);
            List<FindingDto> findings = evaluationService.evaluate(event);
            assertTrue(findings.stream().noneMatch(f -> "D001".equalsIgnoreCase(f.getRuleId())),
                    "Failure " + i + " must not trigger D001 before crossing threshold");
        }

        // 6th failure: count = 6 > 5 -> D001 triggers
        Map<String, Object> rawFail6 = new HashMap<>();
        rawFail6.put("id", "evt-ssh-fail-6");
        rawFail6.put("provider", "Linux-auditd");
        rawFail6.put("action", "ssh_login");
        rawFail6.put("outcome", "failure");
        rawFail6.put("hostname", "LNX-PROD-SRV-01");
        rawFail6.put("host_ip", "192.168.56.102");
        rawFail6.put("src_ip", attackerIp);
        rawFail6.put("username", "root");

        NormalizedEvent event6 = normalizationService.normalize(rawFail6);
        List<FindingDto> findings6 = evaluationService.evaluate(event6);
        assertTrue(findings6.stream().anyMatch(f -> "D001".equalsIgnoreCase(f.getRuleId())),
                "6th failure within sliding window must trigger D001 finding");
    }

    @Test
    @DisplayName("Search & Filtering: Event and finding search functions accurately against real in-memory store")
    void testEventAndFindingSearch() {
        // Ingest two distinct events
        Map<String, Object> winRaw = Map.of(
                "id", "evt-search-win", "provider", "Sysmon", "EventID", 1,
                "hostname", "WIN-WORKSTATION-01", "username", "alice", "Image", "cmd.exe"
        );
        Map<String, Object> lnxRaw = Map.of(
                "id", "evt-search-lnx", "provider", "Linux-auditd",
                "hostname", "LNX-PROD-SRV-01", "username", "bob", "action", "sudo_exec"
        );

        normalizationService.normalize(winRaw);
        normalizationService.normalize(lnxRaw);

        // Search events by provider
        List<NormalizedEvent> sysmonEvents = normalizationService.searchEvents(null, "Sysmon", null, null, 10);
        assertEquals(1, sysmonEvents.size());
        assertEquals("evt-search-win", sysmonEvents.get(0).getId());

        // Search events by query
        List<NormalizedEvent> bobEvents = normalizationService.searchEvents("bob", null, null, null, 10);
        assertEquals(1, bobEvents.size());
        assertEquals("evt-search-lnx", bobEvents.get(0).getId());
    }

    // --- Lightweight Test Double Implementations ---

    private static class StubIocIndicatorRepository implements IocIndicatorRepository {
        private final Map<String, IocIndicator> store;

        StubIocIndicatorRepository(Map<String, IocIndicator> store) { this.store = store; }

        @Override public Optional<IocIndicator> findByIndicatorValue(String indicatorValue) { return Optional.ofNullable(store.get(indicatorValue)); }
        @Override
        public Optional<IocIndicator> findByIndicatorValueIgnoreCase(String indicatorValue) {
            if (indicatorValue == null) return Optional.empty();
            for (Map.Entry<String, IocIndicator> entry : store.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(indicatorValue)) {
                    return Optional.of(entry.getValue());
                }
            }
            return Optional.empty();
        }
        @Override public Optional<IocIndicator> findByIndicatorValueAndIndicatorType(String val, com.blueops.threatintel.IocType type) { return Optional.ofNullable(store.get(val)); }
        @Override public List<IocIndicator> findByStatus(String status) { return new ArrayList<>(store.values()); }
        @Override public List<IocIndicator> findByIndicatorType(com.blueops.threatintel.IocType indicatorType) { return Collections.emptyList(); }
        @Override public boolean existsByIndicatorValueAndIndicatorType(String val, com.blueops.threatintel.IocType type) { return store.containsKey(val); }
        @Override public <S extends IocIndicator> S save(S entity) { store.put(entity.getIndicatorValue(), entity); return entity; }
        @Override public <S extends IocIndicator> List<S> saveAll(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public Optional<IocIndicator> findById(Long aLong) { return Optional.empty(); }
        @Override public boolean existsById(Long aLong) { return false; }
        @Override public List<IocIndicator> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<IocIndicator> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) {}
        @Override public void delete(IocIndicator entity) {}
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends IocIndicator> entities) {}
        @Override public void deleteAll() {}
        @Override public void flush() {}
        @Override public <S extends IocIndicator> S saveAndFlush(S entity) { return entity; }
        @Override public <S extends IocIndicator> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<IocIndicator> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public IocIndicator getOne(Long aLong) { return null; }
        @Override public IocIndicator getById(Long aLong) { return null; }
        @Override public IocIndicator getReferenceById(Long aLong) { return null; }
        @Override public <S extends IocIndicator> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends IocIndicator> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends IocIndicator> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends IocIndicator> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends IocIndicator> long count(Example<S> example) { return 0; }
        @Override public <S extends IocIndicator> boolean exists(Example<S> example) { return false; }
        @Override public <S extends IocIndicator, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<IocIndicator> findAll(Sort sort) { return Collections.emptyList(); }
        @Override public Page<IocIndicator> findAll(Pageable pageable) { return Page.empty(); }
    }

    private static class StubIocMatchRepository implements IocMatchRepository {
        @Override public List<IocMatch> findByIocId(Long iocId) { return Collections.emptyList(); }
        @Override public List<IocMatch> findTop50ByOrderByEventTimestampDesc() { return Collections.emptyList(); }
        @Override public <S extends IocMatch> S save(S entity) { return entity; }
        @Override public <S extends IocMatch> List<S> saveAll(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public Optional<IocMatch> findById(Long aLong) { return Optional.empty(); }
        @Override public boolean existsById(Long aLong) { return false; }
        @Override public List<IocMatch> findAll() { return Collections.emptyList(); }
        @Override public List<IocMatch> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return 0; }
        @Override public void deleteById(Long aLong) {}
        @Override public void delete(IocMatch entity) {}
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends IocMatch> entities) {}
        @Override public void deleteAll() {}
        @Override public void flush() {}
        @Override public <S extends IocMatch> S saveAndFlush(S entity) { return entity; }
        @Override public <S extends IocMatch> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<IocMatch> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public IocMatch getOne(Long aLong) { return null; }
        @Override public IocMatch getById(Long aLong) { return null; }
        @Override public IocMatch getReferenceById(Long aLong) { return null; }
        @Override public <S extends IocMatch> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends IocMatch> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends IocMatch> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends IocMatch> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends IocMatch> long count(Example<S> example) { return 0; }
        @Override public <S extends IocMatch> boolean exists(Example<S> example) { return false; }
        @Override public <S extends IocMatch, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<IocMatch> findAll(Sort sort) { return Collections.emptyList(); }
        @Override public Page<IocMatch> findAll(Pageable pageable) { return Page.empty(); }
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

    private static class StubIncidentRepository implements IncidentRepository {
        @Override public Optional<Incident> findByIncidentNumber(String incidentNumber) { return Optional.empty(); }
        @Override public List<Incident> findByStatus(com.blueops.incidents.IncidentStatus status) { return Collections.emptyList(); }
        @Override public Page<Incident> findByStatus(com.blueops.incidents.IncidentStatus status, Pageable pageable) { return Page.empty(); }
        @Override public long countByStatus(com.blueops.incidents.IncidentStatus status) { return 0; }
        @Override public long countBySeverity(com.blueops.incidents.IncidentSeverity severity) { return 0; }
        @Override public Page<Incident> findFiltered(com.blueops.incidents.IncidentStatus status, com.blueops.incidents.IncidentSeverity severity, Pageable pageable) { return Page.empty(); }
        @Override public Page<Incident> findFilteredAdvanced(com.blueops.incidents.IncidentStatus status, com.blueops.incidents.IncidentSeverity severity, com.blueops.incidents.IncidentPriority priority, String assignedTo, String query, Pageable pageable) { return Page.empty(); }
        @Override public long countActiveIncidents() { return 0; }
        @Override public List<Incident> findActiveByTitleAndAsset(String title, Long assetId) { return Collections.emptyList(); }
        @Override public long countAssetsWithActiveIncidents() { return 0; }
        @Override public List<Incident> findTop5ByOrderByCreatedAtDesc() { return Collections.emptyList(); }
        @Override public List<Incident> findByContainedAtIsNotNullAndCreatedAtIsNotNull() { return Collections.emptyList(); }
        @Override public <S extends Incident> S save(S entity) { entity.setId(100L); return entity; }
        @Override public <S extends Incident> List<S> saveAll(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public Optional<Incident> findById(Long aLong) { return Optional.empty(); }
        @Override public boolean existsById(Long aLong) { return false; }
        @Override public List<Incident> findAll() { return Collections.emptyList(); }
        @Override public List<Incident> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return 0; }
        @Override public void deleteById(Long aLong) {}
        @Override public void delete(Incident entity) {}
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends Incident> entities) {}
        @Override public void deleteAll() {}
        @Override public void flush() {}
        @Override public <S extends Incident> S saveAndFlush(S entity) { return entity; }
        @Override public <S extends Incident> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<Incident> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public Incident getOne(Long aLong) { return null; }
        @Override public Incident getById(Long aLong) { return null; }
        @Override public Incident getReferenceById(Long aLong) { return null; }
        @Override public <S extends Incident> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends Incident> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends Incident> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends Incident> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends Incident> long count(Example<S> example) { return 0; }
        @Override public <S extends Incident> boolean exists(Example<S> example) { return false; }
        @Override public <S extends Incident, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<Incident> findAll(Sort sort) { return Collections.emptyList(); }
        @Override public Page<Incident> findAll(Pageable pageable) { return Page.empty(); }
    }
}
