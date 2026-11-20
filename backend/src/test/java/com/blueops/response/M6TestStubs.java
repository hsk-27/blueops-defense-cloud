package com.blueops.response;

import org.springframework.data.domain.*;
import org.springframework.data.repository.query.FluentQuery;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

/**
 * High-performance in-memory repository stubs for M6 Response & SOAR test suites.
 * Executes in milliseconds on JDK 21 without ByteBuddy agent deadlock.
 */
public class M6TestStubs {

    public static class StubCatalogRepository implements ResponseActionCatalogRepository {
        private final Map<String, ResponseActionDefinition> actionsByCode = new ConcurrentHashMap<>();
        private final Map<Long, ResponseActionDefinition> actionsById = new ConcurrentHashMap<>();
        private final AtomicLong idSeq = new AtomicLong(1);

        public void addAction(ResponseActionDefinition action) {
            if (action.getId() == null) action.setId(idSeq.getAndIncrement());
            actionsByCode.put(action.getActionCode(), action);
            actionsById.put(action.getId(), action);
        }

        @Override
        public Optional<ResponseActionDefinition> findByActionCode(String actionCode) {
            return Optional.ofNullable(actionsByCode.get(actionCode));
        }

        @Override
        public List<ResponseActionDefinition> findByIsEnabledTrue() {
            return actionsById.values().stream().filter(ResponseActionDefinition::isEnabled).toList();
        }

        @Override
        public List<ResponseActionDefinition> findByCategoryAndIsEnabledTrue(String category) {
            return actionsById.values().stream()
                    .filter(a -> a.isEnabled() && a.getCategory().equalsIgnoreCase(category))
                    .toList();
        }

        @Override
        public <S extends ResponseActionDefinition> S save(S entity) {
            addAction(entity);
            return entity;
        }

        @Override public Optional<ResponseActionDefinition> findById(Long id) { return Optional.ofNullable(actionsById.get(id)); }
        @Override public List<ResponseActionDefinition> findAll() { return new ArrayList<>(actionsById.values()); }
        @Override public <S extends ResponseActionDefinition> List<S> saveAll(Iterable<S> entities) { entities.forEach(this::save); return (List<S>) entities; }
        @Override public boolean existsById(Long id) { return actionsById.containsKey(id); }
        @Override public List<ResponseActionDefinition> findAllById(Iterable<Long> ids) { return List.of(); }
        @Override public long count() { return actionsById.size(); }
        @Override public void deleteById(Long id) { actionsById.remove(id); }
        @Override public void delete(ResponseActionDefinition entity) { if (entity != null) actionsById.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) {}
        @Override public void deleteAll(Iterable<? extends ResponseActionDefinition> entities) {}
        @Override public void deleteAll() { actionsById.clear(); actionsByCode.clear(); }
        @Override public void flush() {}
        @Override public <S extends ResponseActionDefinition> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ResponseActionDefinition> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ResponseActionDefinition> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) {}
        @Override public void deleteAllInBatch() {}
        @Override public ResponseActionDefinition getOne(Long id) { return actionsById.get(id); }
        @Override public ResponseActionDefinition getById(Long id) { return actionsById.get(id); }
        @Override public ResponseActionDefinition getReferenceById(Long id) { return actionsById.get(id); }
        @Override public <S extends ResponseActionDefinition> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ResponseActionDefinition> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ResponseActionDefinition> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ResponseActionDefinition> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ResponseActionDefinition> long count(Example<S> example) { return 0; }
        @Override public <S extends ResponseActionDefinition> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ResponseActionDefinition, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ResponseActionDefinition> findAll(Sort sort) { return findAll(); }
        @Override public Page<ResponseActionDefinition> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubTargetRepository implements ResponseTargetRepository {
        private final Map<String, ResponseTargetRecord> targetsByIdentifier = new ConcurrentHashMap<>();
        private final Map<Long, ResponseTargetRecord> targetsById = new ConcurrentHashMap<>();
        private final AtomicLong idSeq = new AtomicLong(1);

        public void addTarget(ResponseTargetRecord target) {
            if (target.getId() == null) target.setId(idSeq.getAndIncrement());
            targetsByIdentifier.put(target.getIdentifier().toLowerCase(), target);
            targetsById.put(target.getId(), target);
        }

        @Override
        public Optional<ResponseTargetRecord> findByTargetId(String targetId) {
            return targetsById.values().stream().filter(t -> t.getTargetId().equalsIgnoreCase(targetId)).findFirst();
        }

        @Override
        public Optional<ResponseTargetRecord> findByIdentifierIgnoreCase(String identifier) {
            if (identifier == null) return Optional.empty();
            return Optional.ofNullable(targetsByIdentifier.get(identifier.toLowerCase()));
        }

        @Override
        public List<ResponseTargetRecord> findByTargetType(String targetType) {
            return targetsById.values().stream().filter(t -> t.getTargetType().equalsIgnoreCase(targetType)).toList();
        }

        @Override
        public List<ResponseTargetRecord> findByTrustStatus(String trustStatus) {
            return targetsById.values().stream().filter(t -> t.getTrustStatus().equalsIgnoreCase(trustStatus)).toList();
        }

        @Override
        public <S extends ResponseTargetRecord> S save(S entity) {
            addTarget(entity);
            return entity;
        }

        @Override public Optional<ResponseTargetRecord> findById(Long id) { return Optional.ofNullable(targetsById.get(id)); }
        @Override public List<ResponseTargetRecord> findAll() { return new ArrayList<>(targetsById.values()); }
        @Override public <S extends ResponseTargetRecord> List<S> saveAll(Iterable<S> entities) { entities.forEach(this::save); return (List<S>) entities; }
        @Override public boolean existsById(Long id) { return targetsById.containsKey(id); }
        @Override public List<ResponseTargetRecord> findAllById(Iterable<Long> ids) { return List.of(); }
        @Override public long count() { return targetsById.size(); }
        @Override public void deleteById(Long id) { targetsById.remove(id); }
        @Override public void delete(ResponseTargetRecord entity) { if (entity != null) targetsById.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) {}
        @Override public void deleteAll(Iterable<? extends ResponseTargetRecord> entities) {}
        @Override public void deleteAll() { targetsById.clear(); targetsByIdentifier.clear(); }
        @Override public void flush() {}
        @Override public <S extends ResponseTargetRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ResponseTargetRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ResponseTargetRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) {}
        @Override public void deleteAllInBatch() {}
        @Override public ResponseTargetRecord getOne(Long id) { return targetsById.get(id); }
        @Override public ResponseTargetRecord getById(Long id) { return targetsById.get(id); }
        @Override public ResponseTargetRecord getReferenceById(Long id) { return targetsById.get(id); }
        @Override public <S extends ResponseTargetRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ResponseTargetRecord> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ResponseTargetRecord> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ResponseTargetRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ResponseTargetRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends ResponseTargetRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ResponseTargetRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ResponseTargetRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<ResponseTargetRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubProposalRepository implements ResponseProposalRepository {
        private final Map<Long, ResponseProposalRecord> proposals = new ConcurrentHashMap<>();
        private final AtomicLong idSeq = new AtomicLong(1);

        @Override
        public <S extends ResponseProposalRecord> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(idSeq.getAndIncrement());
            }
            proposals.put(entity.getId(), entity);
            return entity;
        }

        @Override
        public Optional<ResponseProposalRecord> findById(Long id) {
            return Optional.ofNullable(proposals.get(id));
        }

        @Override
        public Optional<ResponseProposalRecord> findByProposalUuid(String proposalUuid) {
            return proposals.values().stream()
                    .filter(p -> p.getProposalUuid().equalsIgnoreCase(proposalUuid))
                    .findFirst();
        }

        @Override
        public List<ResponseProposalRecord> findByIncidentIdOrderByProposedAtDesc(Long incidentId) {
            return proposals.values().stream()
                    .filter(p -> p.getIncident() != null && Objects.equals(p.getIncident().getId(), incidentId))
                    .sorted(Comparator.comparing(ResponseProposalRecord::getProposedAt).reversed())
                    .toList();
        }

        @Override
        public Page<ResponseProposalRecord> findByStatusOrderByProposedAtDesc(ProposalStatus status, Pageable pageable) {
            List<ResponseProposalRecord> list = proposals.values().stream()
                    .filter(p -> p.getStatus() == status)
                    .sorted(Comparator.comparing(ResponseProposalRecord::getProposedAt).reversed())
                    .toList();
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public List<ResponseProposalRecord> findByStatus(ProposalStatus status) {
            return proposals.values().stream().filter(p -> p.getStatus() == status).toList();
        }

        @Override
        public Page<ResponseProposalRecord> findAllByOrderByProposedAtDesc(Pageable pageable) {
            List<ResponseProposalRecord> list = proposals.values().stream()
                    .sorted(Comparator.comparing(ResponseProposalRecord::getProposedAt).reversed())
                    .toList();
            return new PageImpl<>(list, pageable, list.size());
        }

        @Override
        public boolean existsByActionCodeAndTargetIdentifierAndStatusIn(String actionCode, String targetIdentifier, List<ProposalStatus> statuses) {
            return proposals.values().stream().anyMatch(p ->
                    p.getActionCode().equalsIgnoreCase(actionCode)
                            && p.getTargetIdentifier().equalsIgnoreCase(targetIdentifier)
                            && statuses.contains(p.getStatus()));
        }

        @Override public List<ResponseProposalRecord> findAll() { return new ArrayList<>(proposals.values()); }
        @Override public <S extends ResponseProposalRecord> List<S> saveAll(Iterable<S> entities) { entities.forEach(this::save); return (List<S>) entities; }
        @Override public boolean existsById(Long id) { return proposals.containsKey(id); }
        @Override public List<ResponseProposalRecord> findAllById(Iterable<Long> ids) { return List.of(); }
        @Override public long count() { return proposals.size(); }
        @Override public void deleteById(Long id) { proposals.remove(id); }
        @Override public void delete(ResponseProposalRecord entity) { if (entity != null) proposals.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) {}
        @Override public void deleteAll(Iterable<? extends ResponseProposalRecord> entities) {}
        @Override public void deleteAll() { proposals.clear(); }
        @Override public void flush() {}
        @Override public <S extends ResponseProposalRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ResponseProposalRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ResponseProposalRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) {}
        @Override public void deleteAllInBatch() {}
        @Override public ResponseProposalRecord getOne(Long id) { return proposals.get(id); }
        @Override public ResponseProposalRecord getById(Long id) { return proposals.get(id); }
        @Override public ResponseProposalRecord getReferenceById(Long id) { return proposals.get(id); }
        @Override public <S extends ResponseProposalRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ResponseProposalRecord> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ResponseProposalRecord> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ResponseProposalRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ResponseProposalRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends ResponseProposalRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ResponseProposalRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ResponseProposalRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<ResponseProposalRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }

    public static class StubVerificationRepository implements ResponseVerificationRepository {
        private final Map<Long, ResponseVerificationRecord> verifications = new ConcurrentHashMap<>();
        private final AtomicLong idSeq = new AtomicLong(1);

        @Override
        public <S extends ResponseVerificationRecord> S save(S entity) {
            if (entity.getId() == null) {
                entity.setId(idSeq.getAndIncrement());
            }
            verifications.put(entity.getId(), entity);
            return entity;
        }

        @Override
        public Optional<ResponseVerificationRecord> findById(Long id) {
            return Optional.ofNullable(verifications.get(id));
        }

        @Override
        public Optional<ResponseVerificationRecord> findByVerificationUuid(String verificationUuid) {
            return verifications.values().stream()
                    .filter(v -> v.getVerificationUuid().equalsIgnoreCase(verificationUuid))
                    .findFirst();
        }

        @Override
        public List<ResponseVerificationRecord> findByProposalIdOrderByVerifiedAtDesc(Long proposalId) {
            return verifications.values().stream()
                    .filter(v -> v.getProposal() != null && Objects.equals(v.getProposal().getId(), proposalId))
                    .sorted(Comparator.comparing(ResponseVerificationRecord::getVerifiedAt).reversed())
                    .toList();
        }

        @Override
        public Optional<ResponseVerificationRecord> findTopByProposalIdOrderByVerifiedAtDesc(Long proposalId) {
            return findByProposalIdOrderByVerifiedAtDesc(proposalId).stream().findFirst();
        }

        @Override public List<ResponseVerificationRecord> findAll() { return new ArrayList<>(verifications.values()); }
        @Override public <S extends ResponseVerificationRecord> List<S> saveAll(Iterable<S> entities) { entities.forEach(this::save); return (List<S>) entities; }
        @Override public boolean existsById(Long id) { return verifications.containsKey(id); }
        @Override public List<ResponseVerificationRecord> findAllById(Iterable<Long> ids) { return List.of(); }
        @Override public long count() { return verifications.size(); }
        @Override public void deleteById(Long id) { verifications.remove(id); }
        @Override public void delete(ResponseVerificationRecord entity) { if (entity != null) verifications.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends Long> ids) {}
        @Override public void deleteAll(Iterable<? extends ResponseVerificationRecord> entities) {}
        @Override public void deleteAll() { verifications.clear(); }
        @Override public void flush() {}
        @Override public <S extends ResponseVerificationRecord> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends ResponseVerificationRecord> List<S> saveAllAndFlush(Iterable<S> entities) { return saveAll(entities); }
        @Override public void deleteAllInBatch(Iterable<ResponseVerificationRecord> entities) {}
        @Override public void deleteAllByIdInBatch(Iterable<Long> ids) {}
        @Override public void deleteAllInBatch() {}
        @Override public ResponseVerificationRecord getOne(Long id) { return verifications.get(id); }
        @Override public ResponseVerificationRecord getById(Long id) { return verifications.get(id); }
        @Override public ResponseVerificationRecord getReferenceById(Long id) { return verifications.get(id); }
        @Override public <S extends ResponseVerificationRecord> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends ResponseVerificationRecord> List<S> findAll(Example<S> example) { return List.of(); }
        @Override public <S extends ResponseVerificationRecord> List<S> findAll(Example<S> example, Sort sort) { return List.of(); }
        @Override public <S extends ResponseVerificationRecord> Page<S> findAll(Example<S> example, Pageable pageable) { return Page.empty(); }
        @Override public <S extends ResponseVerificationRecord> long count(Example<S> example) { return 0; }
        @Override public <S extends ResponseVerificationRecord> boolean exists(Example<S> example) { return false; }
        @Override public <S extends ResponseVerificationRecord, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<ResponseVerificationRecord> findAll(Sort sort) { return findAll(); }
        @Override public Page<ResponseVerificationRecord> findAll(Pageable pageable) { return new PageImpl<>(findAll()); }
    }
}
