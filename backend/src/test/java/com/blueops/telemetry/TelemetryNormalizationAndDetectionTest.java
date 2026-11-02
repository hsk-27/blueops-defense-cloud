package com.blueops.telemetry;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.detections.correlation.CorrelationEngine;
import com.blueops.findings.FindingDto;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.incidents.*;
import com.blueops.threatintel.*;
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

class TelemetryNormalizationAndDetectionTest {

    private EventNormalizationService normalizationService;
    private DetectionEvaluationService evaluationService;

    private List<FindingDto> registeredFindings;
    private List<IocMatch> savedMatches;
    private Map<String, IocIndicator> testIocs;

    @BeforeEach
    void setUp() {
        normalizationService = new EventNormalizationService();
        registeredFindings = new ArrayList<>();
        savedMatches = new ArrayList<>();
        testIocs = new HashMap<>();

        // Test double for OpenSearchFindingAdapter
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
        };

        // Stubbed IOC Repository
        IocIndicatorRepository iocRepo = new StubIocIndicatorRepository(testIocs);
        IocMatchRepository matchRepo = new StubIocMatchRepository(savedMatches);

        // Stubbed Asset Repository
        Asset labAsset = new Asset();
        labAsset.setId(1L);
        labAsset.setPersistentId("WIN-ASSET-001");
        labAsset.setHostname("WIN-WORKSTATION-01");
        labAsset.setIpAddress("192.168.56.101");
        AssetRepository assetRepo = new StubAssetRepository(labAsset);

        CorrelationEngine correlationEngine = new CorrelationEngine();

        IncidentRepository incidentRepo = new StubIncidentRepository();
        IncidentService incidentService = new IncidentService(incidentRepo, assetRepo, findingAdapter) {
            @Override
            public IncidentDto createIncident(IncidentCreateRequest request, String creator) {
                IncidentDto inc = new IncidentDto();
                inc.setId(999L);
                inc.setIncidentNumber("INC-2026-TEST");
                inc.setTitle(request.getTitle());
                inc.setSeverity(request.getSeverity().name());
                return inc;
            }

            @Override
            public void addNote(Long incidentId, IncidentNoteRequest request, String author) {
                // stub
            }
        };

        evaluationService = new DetectionEvaluationService(
                iocRepo, matchRepo, findingAdapter,
                correlationEngine, incidentService, incidentRepo, assetRepo
        );
    }

    @Test
    @DisplayName("Normalization: Should normalize raw Sysmon telemetry into Common Event Schema")
    void shouldNormalizeSysmonTelemetry() {
        Map<String, Object> raw = new HashMap<>();
        raw.put("provider", "Sysmon");
        raw.put("EventID", 1);
        raw.put("hostname", "WIN-WORKSTATION-01");
        raw.put("Image", "C:\\Windows\\System32\\cmd.exe");
        raw.put("CommandLine", "cmd.exe /c whoami");
        raw.put("username", "corp\\john");

        NormalizedEvent event = normalizationService.normalize(raw);

        assertNotNull(event);
        assertEquals("Sysmon", event.getEvent().getProvider());
        assertEquals("Windows", event.getHost().getOsName());
        assertEquals("cmd.exe", event.getProcess().getName());
        assertEquals("corp\\john", event.getUser().getName());
    }

    @Test
    @DisplayName("Detection: Should trigger D008 on obfuscated/encoded PowerShell command")
    void shouldDetectEncodedPowerShell() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "Image", "powershell.exe",
                "CommandLine", "powershell.exe -noni -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D008".equals(f.getRuleId())));
        assertEquals("HIGH", findings.get(0).getRuleSeverity());
    }

    @Test
    @DisplayName("Detection: Should trigger D009 on Office document spawning command shell")
    void shouldDetectOfficeSpawningCommandInterpreter() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "ParentImage", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "Image", "C:\\Windows\\System32\\cmd.exe",
                "CommandLine", "cmd.exe /c calc.exe"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D009".equals(f.getRuleId())));
    }

    @Test
    @DisplayName("Detection: Should trigger D011 on Mimikatz LSASS memory harvesting")
    void shouldDetectMimikatzLsassDump() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "Image", "C:\\Temp\\mimikatz.exe",
                "CommandLine", "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D011".equals(f.getRuleId())));
        assertEquals("CRITICAL", findings.get(0).getRuleSeverity());
    }

    @Test
    @DisplayName("Threat Intel: Should trigger D015 and record match on known malicious IP")
    void shouldDetectThreatIntelIocMatch() {
        IocIndicator ioc = new IocIndicator();
        ioc.setIndicatorValue("198.51.100.24");
        ioc.setIndicatorType(IocType.IP);
        ioc.setSource("AlienVault OTX");
        ioc.setSeverity("HIGH");
        ioc.setStatus("ACTIVE");
        ioc.setConfidence(95);

        testIocs.put("198.51.100.24", ioc);

        Map<String, Object> raw = Map.of(
                "provider", "Suricata",
                "hostname", "WIN-WORKSTATION-01",
                "dest_ip", "198.51.100.24",
                "dest_port", 4444
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D015".equals(f.getRuleId())));
        assertEquals(1, savedMatches.size());
        assertEquals("198.51.100.24", savedMatches.get(0).getMatchedValue());
    }

    @Test
    @DisplayName("False Positive Immunity: Benign admin activity should produce 0 findings")
    void shouldProduceNoFindingsOnBenignActivity() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "Image", "C:\\Windows\\System32\\notepad.exe",
                "CommandLine", "notepad.exe C:\\Users\\analyst\\report.txt"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertTrue(findings.isEmpty());
    }

    // --- Lightweight Test Double Implementations ---

    private static class StubIocIndicatorRepository implements IocIndicatorRepository {
        private final Map<String, IocIndicator> store;

        StubIocIndicatorRepository(Map<String, IocIndicator> store) { this.store = store; }

        @Override public Optional<IocIndicator> findByIndicatorValue(String indicatorValue) { return Optional.ofNullable(store.get(indicatorValue)); }
        @Override public Optional<IocIndicator> findByIndicatorValueAndIndicatorType(String val, IocType type) { return Optional.ofNullable(store.get(val)); }
        @Override public List<IocIndicator> findByStatus(String status) { return new ArrayList<>(store.values()); }
        @Override public List<IocIndicator> findByIndicatorType(IocType indicatorType) { return Collections.emptyList(); }
        @Override public boolean existsByIndicatorValueAndIndicatorType(String val, IocType type) { return store.containsKey(val); }
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
        private final List<IocMatch> list;
        StubIocMatchRepository(List<IocMatch> list) { this.list = list; }
        @Override public <S extends IocMatch> S save(S entity) { list.add(entity); return entity; }
        @Override public List<IocMatch> findTop50ByOrderByEventTimestampDesc() { return list; }
        @Override public List<IocMatch> findByIocId(Long iocId) { return Collections.emptyList(); }
        @Override public <S extends IocMatch> List<S> saveAll(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public Optional<IocMatch> findById(Long aLong) { return Optional.empty(); }
        @Override public boolean existsById(Long aLong) { return false; }
        @Override public List<IocMatch> findAll() { return list; }
        @Override public List<IocMatch> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return list.size(); }
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
        @Override public List<Incident> findByStatus(IncidentStatus status) { return Collections.emptyList(); }
        @Override public Page<Incident> findByStatus(IncidentStatus status, Pageable pageable) { return Page.empty(); }
        @Override public long countByStatus(IncidentStatus status) { return 0; }
        @Override public long countBySeverity(IncidentSeverity severity) { return 0; }
        @Override public Page<Incident> findFiltered(IncidentStatus status, IncidentSeverity severity, Pageable pageable) { return Page.empty(); }
        @Override public long countActiveIncidents() { return 0; }
        @Override public List<Incident> findActiveByTitleAndAsset(String title, Long assetId) { return Collections.emptyList(); }
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
