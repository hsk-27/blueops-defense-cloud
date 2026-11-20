package com.blueops.entities;

import com.blueops.correlation.*;
import com.blueops.incidents.IncidentSeverity;
import org.springframework.data.domain.*;
import org.springframework.data.repository.query.FluentQuery;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

public class M5TestStubs {

    public static class StubEntityRepository implements EntityRepository {
        public final Map<Long, EntityRecord> store = new ConcurrentHashMap<>();
        public final Map<String, Long> canonicalIndex = new ConcurrentHashMap<>();
        private final AtomicLong seq = new AtomicLong(1);

        @Override
        public Optional<EntityRecord> findByCanonicalId(String canonicalId) {
            Long id = canonicalIndex.get(canonicalId.toLowerCase());
            return id != null ? Optional.ofNullable(store.get(id)) : Optional.empty();
        }

        @Override
        public boolean existsByCanonicalId(String canonicalId) {
            return canonicalIndex.containsKey(canonicalId.toLowerCase());
        }

        @Override
        public Page<EntityRecord> findByEntityType(EntityType entityType, Pageable pageable) {
            List<EntityRecord> list = store.values().stream()
                    .filter(e -> e.getEntityType() == entityType)
                    .toList();
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public Page<EntityRecord> findFiltered(EntityType type, EntityStatus status, String query, Pageable pageable) {
            List<EntityRecord> list = store.values().stream()
                    .filter(e -> type == null || e.getEntityType() == type)
                    .filter(e -> status == null || e.getStatus() == status)
                    .filter(e -> query == null || e.getDisplayName().toLowerCase().contains(query.toLowerCase())
                            || e.getCanonicalId().toLowerCase().contains(query.toLowerCase()))
                    .toList();
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public <S extends EntityRecord> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(seq.getAndIncrement());
            }
            store.put(entity.getId(), entity);
            canonicalIndex.put(entity.getCanonicalId().toLowerCase(), entity.getId());
            return entity;
        }

        @Override
        public Optional<EntityRecord> findById(Long aLong) {
            return Optional.ofNullable(store.get(aLong));
        }

        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public List<EntityRecord> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<EntityRecord> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(EntityRecord entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends EntityRecord> entities) {}
        @Override public void deleteAll() { store.clear(); canonicalIndex.clear(); }
        @Override public void flush() {}
        @Override public <S extends EntityRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends EntityRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<EntityRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public EntityRecord getOne(Long aLong) { return store.get(aLong); }
        @Override public EntityRecord getById(Long aLong) { return store.get(aLong); }
        @Override public EntityRecord getReferenceById(Long aLong) { return store.get(aLong); }
        @Override public <S extends EntityRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends EntityRecord> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends EntityRecord> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends EntityRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends EntityRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends EntityRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends EntityRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends EntityRecord> List<S> saveAll(Iterable<S> entities) {
            List<S> list = new ArrayList<>();
            for (S s : entities) list.add(save(s));
            return list;
        }
        @Override public List<EntityRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<EntityRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubEntityObservationRepository implements EntityObservationRepository {
        public final Map<Long, EntityObservationRecord> store = new ConcurrentHashMap<>();
        private final AtomicLong seq = new AtomicLong(1);

        @Override
        public Page<EntityObservationRecord> findByEntityIdOrderByObservedAtDesc(Long entityId, Pageable pageable) {
            List<EntityObservationRecord> list = store.values().stream()
                    .filter(o -> o.getEntityId().equals(entityId))
                    .sorted(Comparator.comparing(EntityObservationRecord::getObservedAt).reversed())
                    .toList();
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public Page<EntityObservationRecord> findByCanonicalIdOrderByObservedAtDesc(String canonicalId, Pageable pageable) {
            List<EntityObservationRecord> list = store.values().stream()
                    .filter(o -> o.getCanonicalId().equalsIgnoreCase(canonicalId))
                    .sorted(Comparator.comparing(EntityObservationRecord::getObservedAt).reversed())
                    .toList();
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public List<EntityObservationRecord> findTop50ByCanonicalIdOrderByObservedAtDesc(String canonicalId) {
            return store.values().stream()
                    .filter(o -> o.getCanonicalId().equalsIgnoreCase(canonicalId))
                    .sorted(Comparator.comparing(EntityObservationRecord::getObservedAt).reversed())
                    .limit(50)
                    .toList();
        }

        @Override
        public long countByEntityId(Long entityId) {
            return store.values().stream().filter(o -> o.getEntityId().equals(entityId)).count();
        }

        @Override
        public long countByCanonicalId(String canonicalId) {
            return store.values().stream().filter(o -> o.getCanonicalId().equalsIgnoreCase(canonicalId)).count();
        }

        @Override
        public <S extends EntityObservationRecord> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(seq.getAndIncrement());
            }
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override public Optional<EntityObservationRecord> findById(Long aLong) { return Optional.ofNullable(store.get(aLong)); }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public List<EntityObservationRecord> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<EntityObservationRecord> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(EntityObservationRecord entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends EntityObservationRecord> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public void flush() {}
        @Override public <S extends EntityObservationRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends EntityObservationRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<EntityObservationRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public EntityObservationRecord getOne(Long aLong) { return store.get(aLong); }
        @Override public EntityObservationRecord getById(Long aLong) { return store.get(aLong); }
        @Override public EntityObservationRecord getReferenceById(Long aLong) { return store.get(aLong); }
        @Override public <S extends EntityObservationRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends EntityObservationRecord> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends EntityObservationRecord> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends EntityObservationRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends EntityObservationRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends EntityObservationRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends EntityObservationRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends EntityObservationRecord> List<S> saveAll(Iterable<S> entities) {
            List<S> list = new ArrayList<>();
            for (S s : entities) list.add(save(s));
            return list;
        }
        @Override public List<EntityObservationRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<EntityObservationRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubEntityRelationshipRepository implements EntityRelationshipRepository {
        public final Map<Long, EntityRelationshipRecord> store = new ConcurrentHashMap<>();
        private final AtomicLong seq = new AtomicLong(1);

        @Override
        public Optional<EntityRelationshipRecord> findBySourceCanonicalIdAndTargetCanonicalIdAndRelationType(
                String sourceCanonicalId, String targetCanonicalId, EntityRelationType relationType) {
            return store.values().stream()
                    .filter(r -> r.getSourceCanonicalId().equalsIgnoreCase(sourceCanonicalId)
                            && r.getTargetCanonicalId().equalsIgnoreCase(targetCanonicalId)
                            && r.getRelationType() == relationType)
                    .findFirst();
        }

        @Override
        public List<EntityRelationshipRecord> findBySourceCanonicalIdOrTargetCanonicalId(String sourceCanonicalId, String targetCanonicalId) {
            return store.values().stream()
                    .filter(r -> r.getSourceCanonicalId().equalsIgnoreCase(sourceCanonicalId)
                            || r.getTargetCanonicalId().equalsIgnoreCase(targetCanonicalId))
                    .toList();
        }

        @Override
        public Page<EntityRelationshipRecord> findBySourceCanonicalIdOrTargetCanonicalId(String sourceCanonicalId, String targetCanonicalId, Pageable pageable) {
            List<EntityRelationshipRecord> list = findBySourceCanonicalIdOrTargetCanonicalId(sourceCanonicalId, targetCanonicalId);
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public Page<EntityRelationshipRecord> findFiltered(String source, String target, EntityRelationType relType, Pageable pageable) {
            List<EntityRelationshipRecord> list = store.values().stream()
                    .filter(r -> source == null || r.getSourceCanonicalId().equalsIgnoreCase(source))
                    .filter(r -> target == null || r.getTargetCanonicalId().equalsIgnoreCase(target))
                    .filter(r -> relType == null || r.getRelationType() == relType)
                    .toList();
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public <S extends EntityRelationshipRecord> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(seq.getAndIncrement());
            }
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override public Optional<EntityRelationshipRecord> findById(Long aLong) { return Optional.ofNullable(store.get(aLong)); }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public List<EntityRelationshipRecord> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<EntityRelationshipRecord> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(EntityRelationshipRecord entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends EntityRelationshipRecord> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public void flush() {}
        @Override public <S extends EntityRelationshipRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends EntityRelationshipRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<EntityRelationshipRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public EntityRelationshipRecord getOne(Long aLong) { return store.get(aLong); }
        @Override public EntityRelationshipRecord getById(Long aLong) { return store.get(aLong); }
        @Override public EntityRelationshipRecord getReferenceById(Long aLong) { return store.get(aLong); }
        @Override public <S extends EntityRelationshipRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends EntityRelationshipRecord> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends EntityRelationshipRecord> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends EntityRelationshipRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends EntityRelationshipRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends EntityRelationshipRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends EntityRelationshipRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends EntityRelationshipRecord> List<S> saveAll(Iterable<S> entities) {
            List<S> list = new ArrayList<>();
            for (S s : entities) list.add(save(s));
            return list;
        }
        @Override public List<EntityRelationshipRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<EntityRelationshipRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubCorrelationRepository implements CorrelationRepository {
        public final Map<Long, CorrelationRecord> store = new ConcurrentHashMap<>();
        private final AtomicLong seq = new AtomicLong(1);

        @Override
        public Optional<CorrelationRecord> findByCorrelationId(String correlationId) {
            return store.values().stream()
                    .filter(c -> c.getCorrelationId().equalsIgnoreCase(correlationId))
                    .findFirst();
        }

        @Override
        public List<CorrelationRecord> findByRuleId(String ruleId) {
            return store.values().stream().filter(c -> c.getRuleId().equalsIgnoreCase(ruleId)).toList();
        }

        @Override
        public List<CorrelationRecord> findByPrimaryEntityCanonicalId(String canonicalId) {
            return store.values().stream()
                    .filter(c -> c.getPrimaryEntityCanonicalId().equalsIgnoreCase(canonicalId))
                    .toList();
        }

        @Override
        public Page<CorrelationRecord> findFiltered(IncidentSeverity severity, CorrelationStatus status, String query, Pageable pageable) {
            List<CorrelationRecord> list = store.values().stream()
                    .filter(c -> severity == null || c.getSeverity() == severity)
                    .filter(c -> status == null || c.getStatus() == status)
                    .filter(c -> query == null || c.getCorrelationId().toLowerCase().contains(query.toLowerCase())
                            || c.getRuleName().toLowerCase().contains(query.toLowerCase())
                            || c.getPrimaryEntityCanonicalId().toLowerCase().contains(query.toLowerCase()))
                    .toList();
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public <S extends CorrelationRecord> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(seq.getAndIncrement());
            }
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override public Optional<CorrelationRecord> findById(Long aLong) { return Optional.ofNullable(store.get(aLong)); }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public List<CorrelationRecord> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<CorrelationRecord> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(CorrelationRecord entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends CorrelationRecord> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public void flush() {}
        @Override public <S extends CorrelationRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends CorrelationRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<CorrelationRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public CorrelationRecord getOne(Long aLong) { return store.get(aLong); }
        @Override public CorrelationRecord getById(Long aLong) { return store.get(aLong); }
        @Override public CorrelationRecord getReferenceById(Long aLong) { return store.get(aLong); }
        @Override public <S extends CorrelationRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends CorrelationRecord> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends CorrelationRecord> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends CorrelationRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends CorrelationRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends CorrelationRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends CorrelationRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends CorrelationRecord> List<S> saveAll(Iterable<S> entities) {
            List<S> list = new ArrayList<>();
            for (S s : entities) list.add(save(s));
            return list;
        }
        @Override public List<CorrelationRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<CorrelationRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubCorrelationFindingRepository implements CorrelationFindingRepository {
        public final Map<Long, CorrelationFindingRecord> store = new ConcurrentHashMap<>();
        private final AtomicLong seq = new AtomicLong(1);

        @Override
        public List<CorrelationFindingRecord> findByCorrelationId(Long correlationId) {
            return store.values().stream().filter(f -> f.getCorrelationId().equals(correlationId)).toList();
        }

        @Override
        public List<CorrelationFindingRecord> findByFindingId(String findingId) {
            return store.values().stream().filter(f -> f.getFindingId().equalsIgnoreCase(findingId)).toList();
        }

        @Override
        public boolean existsByCorrelationIdAndFindingId(Long correlationId, String findingId) {
            return store.values().stream().anyMatch(f -> f.getCorrelationId().equals(correlationId) && f.getFindingId().equalsIgnoreCase(findingId));
        }

        @Override
        public <S extends CorrelationFindingRecord> S save(S entity) {
            if (entity.getId() == null) entity.setId(seq.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override public Optional<CorrelationFindingRecord> findById(Long aLong) { return Optional.ofNullable(store.get(aLong)); }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public List<CorrelationFindingRecord> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<CorrelationFindingRecord> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(CorrelationFindingRecord entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends CorrelationFindingRecord> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public void flush() {}
        @Override public <S extends CorrelationFindingRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends CorrelationFindingRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<CorrelationFindingRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public CorrelationFindingRecord getOne(Long aLong) { return store.get(aLong); }
        @Override public CorrelationFindingRecord getById(Long aLong) { return store.get(aLong); }
        @Override public CorrelationFindingRecord getReferenceById(Long aLong) { return store.get(aLong); }
        @Override public <S extends CorrelationFindingRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends CorrelationFindingRecord> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends CorrelationFindingRecord> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends CorrelationFindingRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends CorrelationFindingRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends CorrelationFindingRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends CorrelationFindingRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends CorrelationFindingRecord> List<S> saveAll(Iterable<S> entities) {
            List<S> list = new ArrayList<>();
            for (S s : entities) list.add(save(s));
            return list;
        }
        @Override public List<CorrelationFindingRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<CorrelationFindingRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubCorrelationEntityRepository implements CorrelationEntityRepository {
        public final Map<Long, CorrelationEntityRecord> store = new ConcurrentHashMap<>();
        private final AtomicLong seq = new AtomicLong(1);

        @Override
        public List<CorrelationEntityRecord> findByCorrelationId(Long correlationId) {
            return store.values().stream().filter(e -> e.getCorrelationId().equals(correlationId)).toList();
        }

        @Override
        public List<CorrelationEntityRecord> findByEntityCanonicalId(String entityCanonicalId) {
            return store.values().stream().filter(e -> e.getEntityCanonicalId().equalsIgnoreCase(entityCanonicalId)).toList();
        }

        @Override
        public boolean existsByCorrelationIdAndEntityCanonicalId(Long correlationId, String entityCanonicalId) {
            return store.values().stream().anyMatch(e -> e.getCorrelationId().equals(correlationId) && e.getEntityCanonicalId().equalsIgnoreCase(entityCanonicalId));
        }

        @Override
        public <S extends CorrelationEntityRecord> S save(S entity) {
            if (entity.getId() == null) entity.setId(seq.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override public Optional<CorrelationEntityRecord> findById(Long aLong) { return Optional.ofNullable(store.get(aLong)); }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public List<CorrelationEntityRecord> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<CorrelationEntityRecord> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(CorrelationEntityRecord entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends CorrelationEntityRecord> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public void flush() {}
        @Override public <S extends CorrelationEntityRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends CorrelationEntityRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<CorrelationEntityRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public CorrelationEntityRecord getOne(Long aLong) { return store.get(aLong); }
        @Override public CorrelationEntityRecord getById(Long aLong) { return store.get(aLong); }
        @Override public CorrelationEntityRecord getReferenceById(Long aLong) { return store.get(aLong); }
        @Override public <S extends CorrelationEntityRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends CorrelationEntityRecord> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends CorrelationEntityRecord> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends CorrelationEntityRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends CorrelationEntityRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends CorrelationEntityRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends CorrelationEntityRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends CorrelationEntityRecord> List<S> saveAll(Iterable<S> entities) {
            List<S> list = new ArrayList<>();
            for (S s : entities) list.add(save(s));
            return list;
        }
        @Override public List<CorrelationEntityRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<CorrelationEntityRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubCorrelationRuleRepository implements CorrelationRuleRepository {
        public final Map<Long, CorrelationRuleRecord> store = new ConcurrentHashMap<>();
        private final AtomicLong seq = new AtomicLong(1);

        @Override
        public Optional<CorrelationRuleRecord> findByRuleId(String ruleId) {
            return store.values().stream().filter(r -> r.getRuleId().equalsIgnoreCase(ruleId)).findFirst();
        }

        @Override
        public List<CorrelationRuleRecord> findByEnabledTrue() {
            return store.values().stream().filter(CorrelationRuleRecord::isEnabled).toList();
        }

        @Override
        public <S extends CorrelationRuleRecord> S save(S entity) {
            if (entity.getId() == null) entity.setId(seq.getAndIncrement());
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override public Optional<CorrelationRuleRecord> findById(Long aLong) { return Optional.ofNullable(store.get(aLong)); }
        @Override public boolean existsById(Long aLong) { return store.containsKey(aLong); }
        @Override public List<CorrelationRuleRecord> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<CorrelationRuleRecord> findAllById(Iterable<Long> longs) { return Collections.emptyList(); }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(Long aLong) { store.remove(aLong); }
        @Override public void delete(CorrelationRuleRecord entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> longs) {}
        @Override public void deleteAll(Iterable<? extends CorrelationRuleRecord> entities) {}
        @Override public void deleteAll() { store.clear(); }
        @Override public void flush() {}
        @Override public <S extends CorrelationRuleRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends CorrelationRuleRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return Collections.emptyList(); }
        @Override public void deleteAllInBatch(Iterable<CorrelationRuleRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> longs) {}
        @Override public void deleteAllInBatch() {}
        @Override public CorrelationRuleRecord getOne(Long aLong) { return store.get(aLong); }
        @Override public CorrelationRuleRecord getById(Long aLong) { return store.get(aLong); }
        @Override public CorrelationRuleRecord getReferenceById(Long aLong) { return store.get(aLong); }
        @Override public <S extends CorrelationRuleRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends CorrelationRuleRecord> List<S> findAll(Example<S> example) { return Collections.emptyList(); }
        @Override public <S extends CorrelationRuleRecord> List<S> findAll(Example<S> example, Sort sort) { return Collections.emptyList(); }
        @Override public <S extends CorrelationRuleRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends CorrelationRuleRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends CorrelationRuleRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends CorrelationRuleRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public <S extends CorrelationRuleRecord> List<S> saveAll(Iterable<S> entities) {
            List<S> list = new ArrayList<>();
            for (S s : entities) list.add(save(s));
            return list;
        }
        @Override public List<CorrelationRuleRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<CorrelationRuleRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }
}
