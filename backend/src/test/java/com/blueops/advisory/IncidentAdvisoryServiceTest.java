package com.blueops.advisory;

import com.blueops.assets.Asset;
import com.blueops.findings.FindingDto;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.incidents.*;
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

class IncidentAdvisoryServiceTest {

    private Map<Long, Incident> incidentStore;
    private OpenSearchFindingAdapter findingAdapter;
    private AdvisoryKnowledgeBase knowledgeBase;
    private IncidentAdvisoryService advisoryService;

    @BeforeEach
    void setUp() {
        incidentStore = new HashMap<>();
        IncidentRepository incidentRepository = new StubIncidentRepository(incidentStore);
        findingAdapter = new OpenSearchFindingAdapter(
                new RestTemplateBuilder(), "http://localhost:9200", "admin", "admin", false
        );
        knowledgeBase = new AdvisoryKnowledgeBase();
        advisoryService = new IncidentAdvisoryService(incidentRepository, findingAdapter, knowledgeBase);
    }

    @Test
    @DisplayName("Advisory: Should generate CISA and NIST recommendations with playbooks for C2 and credential attack")
    void shouldGenerateAuthoritativeRecommendationsForC2AndPrivEscalation() {
        // Arrange
        Asset asset = new Asset();
        asset.setId(1L);
        asset.setHostname("LAB-WIN-01");
        asset.setIpAddress("192.168.56.101");

        Incident incident = new Incident();
        incident.setId(10L);
        incident.setIncidentNumber("INC-2026-0010");
        incident.setTitle("Active Multi-Stage C2 and Credential Compromise");
        incident.setSeverity(IncidentSeverity.CRITICAL);
        incident.setStatus(IncidentStatus.INVESTIGATING);
        incident.setPrimaryAsset(asset);

        // Add D015 (C2 IOC) finding
        IncidentFinding f1 = new IncidentFinding(
                incident, "FND-IOC-1001", "D015", "Connection to Known Threat Intelligence Indicator",
                "HIGH", Instant.now(), "DOC-101", "{}"
        );
        // Add D011 (LSASS memory dump) finding
        IncidentFinding f2 = new IncidentFinding(
                incident, "FND-D011-1001", "D011", "LSASS Memory Dumping / Credential Harvesting",
                "CRITICAL", Instant.now(), "DOC-102", "{}"
        );

        incident.getFindings().add(f1);
        incident.getFindings().add(f2);

        FindingDto richFinding1 = new FindingDto(
                "FND-IOC-1001", "D015", "IOC Match", "HIGH",
                "Command and Control", "T1071", "Application Layer Protocol",
                "WIN-ASSET-001", "LAB-WIN-01", Instant.now(), "UNASSIGNED", "DOC-101",
                Map.of("matched_indicator", "198.51.100.24", "sourceIp", "198.51.100.24")
        );
        FindingDto richFinding2 = new FindingDto(
                "FND-D011-1001", "D011", "LSASS Dump", "CRITICAL",
                "Credential Access", "T1003.001", "LSASS Memory",
                "WIN-ASSET-001", "LAB-WIN-01", Instant.now(), "UNASSIGNED", "DOC-102",
                Map.of("user", "SYSTEM")
        );

        findingAdapter.registerFinding(richFinding1);
        findingAdapter.registerFinding(richFinding2);

        incidentStore.put(10L, incident);

        // Act
        List<IncidentRecommendationDto> recommendations = advisoryService.generateRecommendations(10L);

        // Assert
        assertNotNull(recommendations);
        assertFalse(recommendations.isEmpty());

        // Must contain CISA perimeter block (P001)
        assertTrue(recommendations.stream().anyMatch(r ->
                "P001".equals(r.getSuggestedPlaybookCode()) &&
                r.getAuthoritativeSource() == AuthoritativeSource.CISA_IR_PLAYBOOK &&
                r.getCitation().contains("CISA IR Playbook")
        ));

        // Must contain NIST account disabling (P002)
        assertTrue(recommendations.stream().anyMatch(r ->
                "P002".equals(r.getSuggestedPlaybookCode()) &&
                r.getAuthoritativeSource() == AuthoritativeSource.NIST_SP_800_61R2 &&
                r.getCitation().contains("NIST SP 800-61r2")
        ));

        // Must contain RFC 3227 volatile evidence acquisition (P007)
        assertTrue(recommendations.stream().anyMatch(r ->
                "P007".equals(r.getSuggestedPlaybookCode()) &&
                r.getAuthoritativeSource() == AuthoritativeSource.RFC_3227
        ));

        // Top recommendation must be an IMMEDIATE_ACTION
        assertEquals(AdvisoryPriority.IMMEDIATE_ACTION, recommendations.get(0).getPriority());
    }

    @Test
    @DisplayName("Advisory: Should recommend Post-Incident lessons learned and rule calibration when incident is resolved")
    void shouldProvidePostIncidentRecommendationsWhenIncidentResolved() {
        // Arrange
        Incident incident = new Incident();
        incident.setId(20L);
        incident.setIncidentNumber("INC-2026-0020");
        incident.setTitle("Resolved Phishing Incident");
        incident.setSeverity(IncidentSeverity.MEDIUM);
        incident.setStatus(IncidentStatus.RESOLVED);

        incidentStore.put(20L, incident);

        // Act
        List<IncidentRecommendationDto> recommendations = advisoryService.generateRecommendations(20L);

        // Assert
        assertNotNull(recommendations);
        assertTrue(recommendations.stream().anyMatch(r ->
                r.getPhase() == AdvisoryPhase.POST_INCIDENT &&
                r.getCitation().contains("NIST SP 800-61r2 §3.4")
        ));
    }

    @Test
    @DisplayName("Advisory: Should provide standard NIST baseline scoping guidance for unclassified incidents")
    void shouldProvideStandardBaselineGuidanceForUnclassifiedScenarios() {
        // Arrange
        Incident incident = new Incident();
        incident.setId(30L);
        incident.setIncidentNumber("INC-2026-0030");
        incident.setTitle("Unclassified Sensor Anomaly");
        incident.setSeverity(IncidentSeverity.LOW);
        incident.setStatus(IncidentStatus.NEW);

        incidentStore.put(30L, incident);

        // Act
        List<IncidentRecommendationDto> recommendations = advisoryService.generateRecommendations(30L);

        // Assert
        assertNotNull(recommendations);
        assertFalse(recommendations.isEmpty());
        assertTrue(recommendations.stream().anyMatch(r ->
                r.getCitation().contains("NIST SP 800-61r2 §3.2.6")
        ));
    }

    // --- Stub Repository Double ---
    private static class StubIncidentRepository implements IncidentRepository {
        private final Map<Long, Incident> store;

        StubIncidentRepository(Map<Long, Incident> store) {
            this.store = store;
        }

        @Override public Optional<Incident> findById(Long id) { return Optional.ofNullable(store.get(id)); }
        @Override public Optional<Incident> findByIncidentNumber(String incidentNumber) { return Optional.empty(); }
        @Override public List<Incident> findByStatus(IncidentStatus status) { return Collections.emptyList(); }
        @Override public Page<Incident> findByStatus(IncidentStatus status, Pageable pageable) { return Page.empty(); }
        @Override public long countByStatus(IncidentStatus status) { return 0; }
        @Override public long countBySeverity(IncidentSeverity severity) { return 0; }
        @Override public Page<Incident> findFiltered(IncidentStatus status, IncidentSeverity severity, Pageable pageable) { return Page.empty(); }
        @Override public Page<Incident> findFilteredAdvanced(IncidentStatus status, IncidentSeverity severity, IncidentPriority priority, String assignedTo, String query, Pageable pageable) { return Page.empty(); }
        @Override public long countActiveIncidents() { return 0; }
        @Override public List<Incident> findActiveByTitleAndAsset(String title, Long assetId) { return Collections.emptyList(); }
        @Override public long countAssetsWithActiveIncidents() { return 0; }
        @Override public List<Incident> findTop5ByOrderByCreatedAtDesc() { return Collections.emptyList(); }
        @Override public List<Incident> findByContainedAtIsNotNullAndCreatedAtIsNotNull() { return Collections.emptyList(); }
        @Override public <S extends Incident> S save(S entity) { return entity; }
        @Override public <S extends Incident> List<S> saveAll(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public List<Incident> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<Incident> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
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
