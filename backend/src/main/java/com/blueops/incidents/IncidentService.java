package com.blueops.incidents;

import com.blueops.assets.Asset;
import com.blueops.assets.AssetRepository;
import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import com.blueops.findings.FindingDto;
import com.blueops.findings.OpenSearchFindingAdapter;
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
    private final AtomicLong incidentSequence = new AtomicLong(100);

    public IncidentService(IncidentRepository incidentRepository, AssetRepository assetRepository, OpenSearchFindingAdapter findingAdapter) {
        this.incidentRepository = incidentRepository;
        this.assetRepository = assetRepository;
        this.findingAdapter = findingAdapter;
    }

    @Transactional(readOnly = true)
    public Page<IncidentDto> getIncidents(IncidentStatus status, IncidentSeverity severity, Pageable pageable) {
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
        incident.setStatus(IncidentStatus.NEW);
        incident.setCreatedBy(creator);
        incident.setCreatedAt(Instant.now());
        incident.setUpdatedAt(Instant.now());

        if (request.getPrimaryAssetId() != null) {
            Asset asset = assetRepository.findById(request.getPrimaryAssetId()).orElse(null);
            incident.setPrimaryAsset(asset);
        }

        // Attach requested OpenSearch findings
        if (request.getFindingIds() != null && !request.getFindingIds().isEmpty()) {
            for (String fId : request.getFindingIds()) {
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
                }
            }
        }

        // Initial status transition record
        IncidentStatusHistory history = new IncidentStatusHistory(
                incident, "NONE", IncidentStatus.NEW.name(), creator, "Incident created"
        );
        incident.getStatusHistory().add(history);

        Incident saved = incidentRepository.save(incident);
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

        incident.setStatus(target);
        incident.setUpdatedAt(Instant.now());

        if (target == IncidentStatus.CONTAINED && incident.getContainedAt() == null) {
            incident.setContainedAt(Instant.now());
        }
        if (target == IncidentStatus.RESOLVED && incident.getResolvedAt() == null) {
            incident.setResolvedAt(Instant.now());
            if (request.getResolutionRationale() != null) {
                incident.setResolutionRationale(request.getResolutionRationale());
            }
        }

        IncidentStatusHistory history = new IncidentStatusHistory(
                incident, current.name(), target.name(), actor, request.getReason()
        );
        incident.getStatusHistory().add(history);

        return new IncidentDto(incidentRepository.save(incident));
    }

    @Transactional
    public IncidentDto reopenIncident(Long id, String reason, String actor) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));

        if (incident.getStatus() != IncidentStatus.RESOLVED && incident.getStatus() != IncidentStatus.FALSE_POSITIVE) {
            throw new InvalidActionException("Only RESOLVED or FALSE_POSITIVE incidents can be reopened.");
        }

        IncidentStatus prev = incident.getStatus();
        incident.setStatus(IncidentStatus.REOPENED);
        incident.setUpdatedAt(Instant.now());

        IncidentStatusHistory history = new IncidentStatusHistory(
                incident, prev.name(), IncidentStatus.REOPENED.name(), actor, reason != null ? reason : "Incident reopened for further investigation"
        );
        incident.getStatusHistory().add(history);

        return new IncidentDto(incidentRepository.save(incident));
    }

    @Transactional
    public IncidentDto assignIncident(Long id, IncidentAssignRequest request, String actor) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));

        incident.setAssignedTo(request.getAssignedTo());
        incident.setUpdatedAt(Instant.now());

        IncidentNote note = new IncidentNote(incident, actor, "Assigned incident to " + request.getAssignedTo());
        incident.getNotes().add(note);

        return new IncidentDto(incidentRepository.save(incident));
    }

    @Transactional
    public void addNote(Long id, IncidentNoteRequest request, String author) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", "id", id));

        IncidentNote note = new IncidentNote(incident, author, request.getNoteText());
        incident.getNotes().add(note);
        incident.setUpdatedAt(Instant.now());
        incidentRepository.save(incident);
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

        // 3. Notes
        for (IncidentNote n : incident.getNotes()) {
            timeline.add(new IncidentTimelineEntryDto(
                    "NOTE", n.getCreatedAt(), "Analyst Investigation Note",
                    n.getNoteText(), n.getAuthor(), "INFO"
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
}
