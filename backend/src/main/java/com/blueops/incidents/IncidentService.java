package com.blueops.incidents;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.audit.AuditService;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import com.blueops.findings.FindingDto;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.telemetry.EventNormalizationService;
import com.blueops.telemetry.NormalizedEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.Year;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Service
public class IncidentService {

    private final IncidentRepository incidentRepository;
    private final AssetRepository assetRepository;
    private final OpenSearchFindingAdapter findingAdapter;
    private final AuditService auditService;
    private final EventNormalizationService eventNormalizationService;
    private final AtomicLong incidentSequence = new AtomicLong(100);

    @Autowired
    public IncidentService(IncidentRepository incidentRepository,
                           AssetRepository assetRepository,
                           OpenSearchFindingAdapter findingAdapter,
                           @Autowired(required = false) AuditService auditService,
                           @Autowired(required = false) EventNormalizationService eventNormalizationService) {
        this.incidentRepository = incidentRepository;
        this.assetRepository = assetRepository;
        this.findingAdapter = findingAdapter;
        this.auditService = auditService;
        this.eventNormalizationService = eventNormalizationService;
    }

    public IncidentService(IncidentRepository incidentRepository, AssetRepository assetRepository, OpenSearchFindingAdapter findingAdapter) {
        this(incidentRepository, assetRepository, findingAdapter, null, null);
    }

    @Transactional(readOnly = true)
    public Page<IncidentDto> getIncidents(IncidentStatus status, IncidentSeverity severity, Pageable pageable) {
        return getIncidents(status, severity, null, null, null, pageable);
    }

    @Transactional(readOnly = true)
    public Page<IncidentDto> getIncidents(IncidentStatus status, IncidentSeverity severity, IncidentPriority priority, String assignedTo, String search, Pageable pageable) {
        if (priority != null || (assignedTo != null && !assignedTo.isBlank()) || (search != null && !search.isBlank())) {
            String q = (search != null && !search.isBlank()) ? search.trim() : null;
            String assignee = (assignedTo != null && !assignedTo.isBlank()) ? assignedTo.trim() : null;
            return incidentRepository.findFilteredAdvanced(status, severity, priority, assignee, q, pageable).map(IncidentDto::new);
        }
        return incidentRepository.findFiltered(status, severity, pageable).map(IncidentDto::new);
    }

    @Transactional(readOnly = true)
    public IncidentDto getIncidentById(Long id) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));
        return new IncidentDto(incident);
    }

    @Transactional
    public IncidentDto createIncident(IncidentCreateRequest request, String creator) {
        Incident incident = new Incident();
        String incNumber = String.format("INC-%d-%04d", Year.now().getValue(), incidentSequence.incrementAndGet());
        incident.setIncidentNumber(incNumber);
        incident.setTitle(request.getTitle());
        incident.setDescription(request.getDescription());
        incident.setSeverity(request.getSeverity());
        incident.setPriority(request.getPriority() != null ? request.getPriority() : IncidentPriority.fromSeverity(request.getSeverity()));
        incident.setStatus(IncidentStatus.NEW);
        incident.setCreatedBy(creator != null ? creator : "SYSTEM");
        incident.setCreatedAt(Instant.now());
        incident.setUpdatedAt(Instant.now());

        if (request.getPrimaryAssetId() != null) {
            Asset asset = assetRepository.findById(request.getPrimaryAssetId()).orElse(null);
            incident.setPrimaryAsset(asset);
        }

        // Collect all requested findings to link
        Set<String> findingIdsToLink = new LinkedHashSet<>();
        if (request.getSourceFindingId() != null && !request.getSourceFindingId().isBlank()) {
            findingIdsToLink.add(request.getSourceFindingId().trim());
        }
        if (request.getFindingIds() != null) {
            findingIdsToLink.addAll(request.getFindingIds());
        }

        // Attach requested OpenSearch findings
        for (String fId : findingIdsToLink) {
            Optional<FindingDto> findingOpt = findingAdapter.getFindingById(fId);
            if (findingOpt.isPresent()) {
                FindingDto f = findingOpt.get();
                IncidentFinding incFinding = new IncidentFinding(
                        incident, f.getFindingId(), f.getRuleId(), f.getRuleName(),
                        f.getRuleSeverity(), f.getTimestamp(), f.getRelatedDocId(),
                        f.getDetails() != null ? f.getDetails().toString() : null
                );
                incident.getFindings().add(incFinding);
                f.setStatus("LINKED_TO_INCIDENT");
                findingAdapter.registerFinding(f);

                // Auto-resolve primary asset if not explicitly provided
                if (incident.getPrimaryAsset() == null && f.getAssetId() != null) {
                    assetRepository.findByPersistentId(f.getAssetId()).ifPresent(incident::setPrimaryAsset);
                }
            }
        }

        // Initial status transition record
        IncidentStatusHistory history = new IncidentStatusHistory(
                incident, "NONE", IncidentStatus.NEW.name(), creator, "Incident created"
        );
        incident.getStatusHistory().add(history);

        Incident saved = incidentRepository.save(incident);
        if (auditService != null) {
            auditService.recordEvent(creator, "INCIDENT_CREATED", "Incident", String.valueOf(saved.getId()), null,
                    "Created incident " + saved.getIncidentNumber() + ": " + saved.getTitle() + " (" + saved.getSeverity() + ")");
        }
        return new IncidentDto(saved);
    }

    @Transactional
    public IncidentDto updateStatus(Long id, IncidentStatusUpdateRequest request, String actor) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));

        IncidentStatus current = incident.getStatus();
        IncidentStatus target = request.getStatus();

        if (!current.canTransitionTo(target)) {
            throw new InvalidActionException(String.format("Invalid status transition from %s to %s", current, target));
        }

        if (target == IncidentStatus.RESOLVED) {
            if (request.getResolutionRationale() == null || request.getResolutionRationale().trim().isEmpty()) {
                throw new InvalidActionException("Resolution rationale is required when resolving an incident.");
            }
            incident.setResolvedAt(Instant.now());
            incident.setResolutionRationale(request.getResolutionRationale().trim());
        }

        if (target == IncidentStatus.CLOSED) {
            if (current != IncidentStatus.RESOLVED && current != IncidentStatus.FALSE_POSITIVE) {
                throw new InvalidActionException("Only RESOLVED or FALSE_POSITIVE incidents can be closed.");
            }
            incident.setClosedAt(Instant.now());
            incident.setClosedBy(actor);
            if (request.getClosureNotes() != null && !request.getClosureNotes().isBlank()) {
                incident.setClosureNotes(request.getClosureNotes().trim());
            }
        }

        if (target == IncidentStatus.CONTAINED && incident.getContainedAt() == null) {
            incident.setContainedAt(Instant.now());
        }

        incident.setStatus(target);
        incident.setUpdatedAt(Instant.now());

        IncidentStatusHistory history = new IncidentStatusHistory(
                incident, current.name(), target.name(), actor, request.getReason()
        );
        incident.getStatusHistory().add(history);

        Incident saved = incidentRepository.save(incident);
        if (auditService != null) {
            auditService.recordEvent(actor, "INCIDENT_STATUS_CHANGE", "Incident", String.valueOf(saved.getId()), null,
                    "Transitioned from " + current + " to " + target + ". Reason: " + request.getReason());
        }
        return new IncidentDto(saved);
    }

    @Transactional
    public IncidentDto reopenIncident(Long id, String reason, String actor) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));

        if (incident.getStatus() != IncidentStatus.RESOLVED && incident.getStatus() != IncidentStatus.FALSE_POSITIVE && incident.getStatus() != IncidentStatus.CLOSED) {
            throw new InvalidActionException("Only RESOLVED, FALSE_POSITIVE, or CLOSED incidents can be reopened.");
        }

        IncidentStatus prev = incident.getStatus();
        incident.setStatus(IncidentStatus.REOPENED);
        incident.setUpdatedAt(Instant.now());

        IncidentStatusHistory history = new IncidentStatusHistory(
                incident, prev.name(), IncidentStatus.REOPENED.name(), actor, reason != null ? reason : "Incident reopened for further investigation"
        );
        incident.getStatusHistory().add(history);

        Incident saved = incidentRepository.save(incident);
        if (auditService != null) {
            auditService.recordEvent(actor, "INCIDENT_REOPENED", "Incident", String.valueOf(saved.getId()), null,
                    "Incident reopened from " + prev + ". Reason: " + reason);
        }
        return new IncidentDto(saved);
    }

    @Transactional
    public IncidentDto assignIncident(Long id, IncidentAssignRequest request, String actor) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));

        String prevAssignee = incident.getAssignedTo();
        String targetAssignee = request.getAssignedTo();
        if (targetAssignee != null && (targetAssignee.isBlank() || targetAssignee.equalsIgnoreCase("unassigned") || targetAssignee.equalsIgnoreCase("none"))) {
            targetAssignee = null;
        }

        incident.setAssignedTo(targetAssignee);
        incident.setUpdatedAt(Instant.now());

        String noteText = targetAssignee != null
                ? "Assigned incident to " + targetAssignee + (prevAssignee != null ? " (reassigned from " + prevAssignee + ")" : "")
                : "Unassigned incident from " + (prevAssignee != null ? prevAssignee : "previous assignee");

        IncidentNote note = new IncidentNote(incident, actor, noteText);
        incident.getNotes().add(note);

        Incident saved = incidentRepository.save(incident);
        if (auditService != null) {
            auditService.recordEvent(actor, "INCIDENT_ASSIGNED", "Incident", String.valueOf(saved.getId()), null,
                    noteText);
        }
        return new IncidentDto(saved);
    }

    @Transactional
    public void addNote(Long id, IncidentNoteRequest request, String author) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));

        if (request.getNoteText() == null || request.getNoteText().trim().isEmpty()) {
            throw new InvalidActionException("Note text cannot be empty.");
        }

        IncidentNote note = new IncidentNote(incident, author, request.getNoteText().trim());
        incident.getNotes().add(note);
        incident.setUpdatedAt(Instant.now());
        incidentRepository.save(incident);

        if (auditService != null) {
            auditService.recordEvent(author, "INCIDENT_NOTE_ADDED", "Incident", String.valueOf(incident.getId()), null,
                    "Added investigation note to " + incident.getIncidentNumber());
        }
    }

    @Transactional(readOnly = true)
    public List<IncidentTimelineEntryDto> getTimeline(Long id) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));

        List<IncidentTimelineEntryDto> timeline = new ArrayList<>();

        // 1. Findings
        for (IncidentFinding f : incident.getFindings()) {
            timeline.add(new IncidentTimelineEntryDto(
                    "FINDING", f.getDetectedAt(), "Detection: " + f.getRuleName(),
                    "Rule Code: " + f.getRuleCode() + " | Raw Doc: " + f.getRawDocumentId(),
                    "Detector", f.getSeverity()
            ));
        }

        // 2. Status Transitions
        for (IncidentStatusHistory h : incident.getStatusHistory()) {
            timeline.add(new IncidentTimelineEntryDto(
                    "STATUS_CHANGE", h.getTransitionedAt(), "Status Changed to " + h.getToStatus(),
                    h.getReason() != null ? h.getReason() : "Transitioned from " + h.getFromStatus(),
                    h.getActor(), "INFO"
            ));
        }

        // 4. Notes
        for (IncidentNote n : incident.getNotes()) {
            timeline.add(new IncidentTimelineEntryDto(
                    "NOTE", n.getCreatedAt(), "Analyst Investigation Note",
                    n.getNoteText(), n.getAuthor(), "INFO"
            ));
        }

        // 5. Closure
        if (incident.getClosedAt() != null) {
            timeline.add(new IncidentTimelineEntryDto(
                    "CLOSURE", incident.getClosedAt(), "Incident Closed",
                    incident.getClosureNotes() != null ? incident.getClosureNotes() : "Investigation formally closed post-verification",
                    incident.getClosedBy() != null ? incident.getClosedBy() : "System", "INFO"
            ));
        }

        timeline.sort(Comparator.comparing(IncidentTimelineEntryDto::getTimestamp));
        return timeline;
    }

    @Transactional(readOnly = true)
    public List<IncidentFinding> getIncidentFindings(Long id) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));
        return incident.getFindings();
    }

    @Transactional
    public IncidentFinding attachFinding(Long incidentId, String findingId, String actor) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", incidentId));

        boolean alreadyAttached = incident.getFindings().stream()
                .anyMatch(f -> f.getOpensearchFindingId().equalsIgnoreCase(findingId));
        if (alreadyAttached) {
            throw new InvalidActionException("Finding " + findingId + " is already attached to this incident.");
        }

        FindingDto f = findingAdapter.getFindingById(findingId)
                .orElseThrow(() -> new ResourceNotFoundException("Finding", "id", findingId));

        IncidentFinding incFinding = new IncidentFinding(
                incident, f.getFindingId(), f.getRuleId(), f.getRuleName(),
                f.getRuleSeverity(), f.getTimestamp(), f.getRelatedDocId(),
                f.getDetails() != null ? f.getDetails().toString() : null
        );
        incident.getFindings().add(incFinding);
        f.setStatus("LINKED_TO_INCIDENT");
        findingAdapter.registerFinding(f);

        IncidentStatusHistory history = new IncidentStatusHistory(
                incident, incident.getStatus().name(), incident.getStatus().name(),
                actor, "Attached finding " + f.getFindingId() + " (" + f.getRuleName() + ") as evidence"
        );
        incident.getStatusHistory().add(history);
        incident.setUpdatedAt(Instant.now());
        incidentRepository.save(incident);

        if (auditService != null) {
            auditService.recordEvent(actor, "INCIDENT_FINDING_ATTACHED", "Incident", String.valueOf(incident.getId()), null,
                    "Attached finding " + f.getFindingId() + " to incident " + incident.getIncidentNumber());
        }

        return incFinding;
    }

    @Transactional
    public void detachFinding(Long incidentId, String findingId, String actor) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", incidentId));

        IncidentFinding target = incident.getFindings().stream()
                .filter(f -> f.getOpensearchFindingId().equalsIgnoreCase(findingId))
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("IncidentFinding", "findingId", findingId));

        incident.getFindings().remove(target);

        Optional<FindingDto> fOpt = findingAdapter.getFindingById(findingId);
        if (fOpt.isPresent()) {
            FindingDto f = fOpt.get();
            f.setStatus("OPEN");
            findingAdapter.registerFinding(f);
        }

        IncidentStatusHistory history = new IncidentStatusHistory(
                incident, incident.getStatus().name(), incident.getStatus().name(),
                actor, "Detached finding " + findingId + " from incident"
        );
        incident.getStatusHistory().add(history);
        incident.setUpdatedAt(Instant.now());
        incidentRepository.save(incident);

        if (auditService != null) {
            auditService.recordEvent(actor, "INCIDENT_FINDING_DETACHED", "Incident", String.valueOf(incident.getId()), null,
                    "Detached finding " + findingId + " from incident " + incident.getIncidentNumber());
        }
    }

    @Transactional(readOnly = true)
    public List<IncidentEvidenceDto> getIncidentEvidence(Long incidentId) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", incidentId));

        List<IncidentEvidenceDto> evidenceList = new ArrayList<>();
        for (IncidentFinding f : incident.getFindings()) {
            String docId = f.getRawDocumentId();
            NormalizedEvent ev = null;
            if (eventNormalizationService != null && docId != null) {
                ev = eventNormalizationService.getEventById(docId).orElse(null);
            }

            String rawPayload = (ev != null && ev.getEvent() != null) ? ev.getEvent().getOriginal() : null;
            String host = (ev != null && ev.getHost() != null) ? ev.getHost().getName() : (incident.getPrimaryAsset() != null ? incident.getPrimaryAsset().getHostname() : "UNKNOWN");
            String srcIp = (ev != null && ev.getSource() != null) ? ev.getSource().getIp() : null;
            String user = (ev != null && ev.getUser() != null) ? ev.getUser().getName() : null;
            String proc = (ev != null && ev.getProcess() != null) ? ev.getProcess().getCommandLine() : null;
            String provider = (ev != null && ev.getEvent() != null) ? ev.getEvent().getProvider() : "DETECTION_ENGINE";

            Map<String, Object> attrs = new HashMap<>();
            if (f.getDetailsJson() != null) {
                attrs.put("findingDetails", f.getDetailsJson());
            }
            if (ev != null) {
                attrs.put("eventId", ev.getId());
                if (ev.getHost() != null) attrs.put("os", ev.getHost().getOsName());
                if (ev.getProcess() != null) attrs.put("processExecutable", ev.getProcess().getExecutable());
            }

            evidenceList.add(new IncidentEvidenceDto(
                    "EVD-" + incidentId + "-" + f.getOpensearchFindingId(),
                    "TELEMETRY_EVENT",
                    f.getOpensearchFindingId(),
                    f.getRuleCode(),
                    f.getRuleName(),
                    f.getSeverity(),
                    f.getDetectedAt(),
                    provider,
                    host,
                    srcIp,
                    user,
                    proc,
                    rawPayload,
                    attrs
            ));
        }
        return evidenceList;
    }
}
