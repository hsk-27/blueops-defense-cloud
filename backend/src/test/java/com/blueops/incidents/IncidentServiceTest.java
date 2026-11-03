package com.blueops.incidents;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.findings.FindingDto;
import com.blueops.findings.OpenSearchFindingAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.client.RestTemplateBuilder;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class IncidentServiceTest {

    private IncidentService incidentService;
    private StubIncidentRepository incidentRepo;
    private StubAssetRepository assetRepo;
    private OpenSearchFindingAdapter findingAdapter;

    @BeforeEach
    void setUp() {
        incidentRepo = new StubIncidentRepository();
        assetRepo = new StubAssetRepository();
        findingAdapter = new OpenSearchFindingAdapter(
                new RestTemplateBuilder(), "http://localhost:9200", "admin", "admin", false
        );

        incidentService = new IncidentService(incidentRepo, assetRepo, findingAdapter);
    }

    @Test
    @DisplayName("Should create incident and generate initial timeline status")
    void shouldCreateIncident() {
        IncidentCreateRequest req = new IncidentCreateRequest();
        req.setTitle("Suspicious Activity on Lab VM");
        req.setDescription("Potential malware outbreak");
        req.setSeverity(IncidentSeverity.HIGH);

        IncidentDto created = incidentService.createIncident(req, "analyst.john");

        assertNotNull(created);
        assertNotNull(created.getId());
        assertEquals("Suspicious Activity on Lab VM", created.getTitle());
        assertEquals("HIGH", created.getSeverity());
        assertEquals("NEW", created.getStatus());

        List<IncidentTimelineEntryDto> timeline = incidentService.getTimeline(created.getId());
        assertFalse(timeline.isEmpty());
        assertEquals("STATUS_CHANGE", timeline.get(0).getType());
    }

    @Test
    @DisplayName("Should attach finding to active incident and update timeline")
    void shouldAttachFindingToIncident() {
        IncidentCreateRequest req = new IncidentCreateRequest();
        req.setTitle("Investigating Suspicious Beaconing");
        req.setSeverity(IncidentSeverity.HIGH);
        IncidentDto created = incidentService.createIncident(req, "analyst.john");

        FindingDto finding = new FindingDto(
                "FND-TEST-999", "D015", "Connection to Known Threat Intel Indicator", "HIGH",
                "Command and Control", "T1071", "Application Layer Protocol",
                "WIN-01", "LAB-WIN-01", Instant.now(), "UNASSIGNED", "DOC-999", null
        );
        findingAdapter.registerFinding(finding);

        IncidentFinding attached = incidentService.attachFinding(created.getId(), "FND-TEST-999", "analyst.john");

        assertNotNull(attached);
        assertEquals("FND-TEST-999", attached.getOpensearchFindingId());
        assertEquals("D015", attached.getRuleCode());

        List<IncidentFinding> findings = incidentService.getIncidentFindings(created.getId());
        assertEquals(1, findings.size());
        assertEquals("FND-TEST-999", findings.get(0).getOpensearchFindingId());

        // Reject duplicate attachment
        assertThrows(InvalidActionException.class, () ->
                incidentService.attachFinding(created.getId(), "FND-TEST-999", "analyst.john")
        );
    }

    @Test
    @DisplayName("Should add analyst notes and update timeline")
    void shouldAddNoteToIncident() {
        IncidentCreateRequest req = new IncidentCreateRequest();
        req.setTitle("Root Shell Escalation");
        req.setSeverity(IncidentSeverity.CRITICAL);
        IncidentDto created = incidentService.createIncident(req, "analyst.john");

        IncidentNoteRequest noteReq = new IncidentNoteRequest();
        noteReq.setNoteText("Quarantined host network adapter via playbook P003");
        incidentService.addNote(created.getId(), noteReq, "analyst.john");

        List<IncidentTimelineEntryDto> timeline = incidentService.getTimeline(created.getId());
        boolean hasNote = timeline.stream().anyMatch(t -> "NOTE".equals(t.getType()) && t.getDescription().contains("P003"));
        assertTrue(hasNote);
    }

    // -------------------------------------------------------------
    // Test Doubles (Avoid Mockito Dynamic Agent Delay on Java 21)
    // -------------------------------------------------------------
    static class StubIncidentRepository implements IncidentRepository {
        private final Map<Long, Incident> store = new HashMap<>();
        private long idGen = 1L;

        @Override
        @SuppressWarnings("unchecked")
        public <S extends Incident> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(idGen++);
            }
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override
        public Optional<Incident> findById(Long id) {
            return Optional.ofNullable(store.get(id));
        }

        @Override public Optional<Incident> findByIncidentNumber(String incidentNumber) { return Optional.empty(); }
        @Override public long countByStatus(IncidentStatus status) { return store.values().stream().filter(i -> i.getStatus() == status).count(); }
        @Override public List<Incident> findByStatus(IncidentStatus status) { return store.values().stream().filter(i -> i.getStatus() == status).toList(); }
        @Override public org.springframework.data.domain.Page<Incident> findByStatus(IncidentStatus status, org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
        @Override public org.springframework.data.domain.Page<Incident> findFiltered(IncidentStatus status, IncidentSeverity severity, org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
        @Override public long countActiveIncidents() { return 0; }
        @Override public long countBySeverity(IncidentSeverity severity) { return 0; }
        @Override public long countAssetsWithActiveIncidents() { return 0; }
        @Override public List<Incident> findTop5ByOrderByCreatedAtDesc() { return List.of(); }
        @Override public List<Incident> findByContainedAtIsNotNullAndCreatedAtIsNotNull() { return List.of(); }
        @Override public List<Incident> findActiveByTitleAndAsset(String title, Long assetId) { return List.of(); }
        @Override public List<Incident> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<Incident> findAll(org.springframework.data.domain.Sort sort) { return List.of(); }
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
        @Override public <S extends Incident> Optional<S> findOne(org.springframework.data.domain.Example<S> example) { return Optional.empty(); }
        @Override public <S extends Incident> List<S> findAll(org.springframework.data.domain.Example<S> example) { return List.of(); }
        @Override public <S extends Incident> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) { return List.of(); }
        @Override public <S extends Incident> org.springframework.data.domain.Page<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
        @Override public <S extends Incident> long count(org.springframework.data.domain.Example<S> example) { return 0; }
        @Override public <S extends Incident> boolean exists(org.springframework.data.domain.Example<S> example) { return false; }
        @Override public <S extends Incident, R> R findBy(org.springframework.data.domain.Example<S> example, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(Incident entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends Incident> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public org.springframework.data.domain.Page<Incident> findAll(org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
    }

    static class StubAssetRepository implements AssetRepository {
        @Override public Optional<Asset> findByPersistentId(String persistentId) { return Optional.empty(); }
        @Override public Optional<Asset> findByHostname(String hostname) { return Optional.empty(); }
        @Override public Optional<Asset> findByHostnameIgnoreCase(String hostname) { return Optional.empty(); }
        @Override public Optional<Asset> findByIpAddress(String ipAddress) { return Optional.empty(); }
        @Override public boolean existsByPersistentId(String persistentId) { return false; }
        @Override public void flush() {}
        @Override public <S extends Asset> S saveAndFlush(S entity) { return entity; }
        @Override public <S extends Asset> List<S> saveAllAndFlush(Iterable<S> entities) { return List.of(); }
        @Override public void deleteAllInBatch(Iterable<Asset> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public Asset getOne(Long aLong) { return null; }
        @Override public Asset getById(Long aLong) { return null; }
        @Override public Asset getReferenceById(Long aLong) { return null; }
        @Override public <S extends Asset> Optional<S> findOne(org.springframework.data.domain.Example<S> example) { return Optional.empty(); }
        @Override public <S extends Asset> List<S> findAll(org.springframework.data.domain.Example<S> example) { return List.of(); }
        @Override public <S extends Asset> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) { return List.of(); }
        @Override public <S extends Asset> org.springframework.data.domain.Page<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
        @Override public <S extends Asset> long count(org.springframework.data.domain.Example<S> example) { return 0; }
        @Override public <S extends Asset> boolean exists(org.springframework.data.domain.Example<S> example) { return false; }
        @Override public <S extends Asset, R> R findBy(org.springframework.data.domain.Example<S> example, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends Asset> S save(S entity) { return entity; }
        @Override public <S extends Asset> List<S> saveAll(Iterable<S> entities) { return List.of(); }
        @Override public Optional<Asset> findById(Long aLong) { return Optional.empty(); }
        @Override public boolean existsById(Long aLong) { return false; }
        @Override public List<Asset> findAll() { return List.of(); }
        @Override public List<Asset> findAllById(Iterable<Long> longs) { return List.of(); }
        @Override public long count() { return 0; }
        @Override public void deleteById(Long aLong) {}
        @Override public void delete(Asset entity) {}
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends Asset> entities) {}
        @Override public void deleteAll() {}
        @Override public List<Asset> findAll(org.springframework.data.domain.Sort sort) { return List.of(); }
        @Override public org.springframework.data.domain.Page<Asset> findAll(org.springframework.data.domain.Pageable pageable) { return org.springframework.data.domain.Page.empty(); }
    }
}
