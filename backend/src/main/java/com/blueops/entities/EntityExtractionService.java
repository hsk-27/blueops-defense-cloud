package com.blueops.entities;

import com.blueops.findings.FindingDto;
import com.blueops.telemetry.NormalizedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Service
public class EntityExtractionService {

    private static final Logger log = LoggerFactory.getLogger(EntityExtractionService.class);
    private final EntityResolutionService resolutionService;

    public EntityExtractionService(EntityResolutionService resolutionService) {
        this.resolutionService = resolutionService;
    }

    /**
     * Extracts canonical entities, observations, and relationships from an ingested NormalizedEvent.
     * Wrapped in a defensive boundary so extraction failures never destabilize the core ingestion spine.
     */
    @Transactional
    public List<EntityRecord> extractFromEvent(NormalizedEvent event) {
        List<EntityRecord> extracted = new ArrayList<>();
        if (event == null) return extracted;

        try {
            String eventId = event.getId() != null ? event.getId() : (event.getEvent() != null ? event.getEvent().getId() : null);
            Instant eventTime = event.getTimestamp() != null ? event.getTimestamp() : Instant.now();
            String rawRef = event.getEvent() != null ? event.getEvent().getProvider() : "telemetry";

            EntityRecord hostEntity = null;
            EntityRecord userEntity = null;
            EntityRecord processEntity = null;
            EntityRecord srcIpEntity = null;
            EntityRecord destIpEntity = null;
            EntityRecord domainEntity = null;
            EntityRecord fileEntity = null;
            EntityRecord hashEntity = null;

            // 1. Host Extraction
            String hostname = null;
            if (event.getHost() != null && event.getHost().getName() != null) {
                hostname = event.getHost().getName();
            } else if (event.getHost() != null && event.getHost().getId() != null) {
                hostname = event.getHost().getId();
            }

            if (hostname != null && !hostname.trim().isEmpty()) {
                String hostCanonicalId = resolutionService.buildHostCanonicalId(hostname);
                Map<String, Object> hostAttrs = new HashMap<>();
                if (event.getHost() != null) {
                    if (event.getHost().getIp() != null) hostAttrs.put("ip", event.getHost().getIp());
                    if (event.getHost().getOsName() != null) hostAttrs.put("os_name", event.getHost().getOsName());
                    if (event.getHost().getOsVersion() != null) hostAttrs.put("os_version", event.getHost().getOsVersion());
                }
                hostEntity = resolutionService.resolveOrCreateEntity(EntityType.HOST, hostCanonicalId, hostname, hostAttrs, 0.0);
                resolutionService.recordObservation(hostEntity, "TELEMETRY_EVENT", eventId, hostname, rawRef, hostAttrs, 1.0, eventTime);
                extracted.add(hostEntity);
            }

            // 2. User Extraction
            if (event.getUser() != null && event.getUser().getName() != null && !event.getUser().getName().trim().isEmpty()) {
                String username = event.getUser().getName().trim();
                if (event.getUser().getDomain() != null && !event.getUser().getDomain().trim().isEmpty()
                        && !username.contains("\\") && !username.contains("@")) {
                    username = event.getUser().getDomain().trim() + "\\" + username;
                }
                String userCanonicalId = resolutionService.buildUserCanonicalId(username);
                Map<String, Object> userAttrs = new HashMap<>();
                if (event.getUser().getDomain() != null) userAttrs.put("domain", event.getUser().getDomain());
                if (event.getUser().getId() != null) userAttrs.put("id", event.getUser().getId());

                userEntity = resolutionService.resolveOrCreateEntity(EntityType.USER, userCanonicalId, username, userAttrs, 0.0);
                resolutionService.recordObservation(userEntity, "TELEMETRY_EVENT", eventId, hostname, rawRef, userAttrs, 1.0, eventTime);
                extracted.add(userEntity);

                // Relationship: HOST_HAS_USER or USER_AUTHENTICATED_TO
                if (hostEntity != null) {
                    boolean isAuth = event.getEvent() != null && event.getEvent().getCategory() != null
                            && event.getEvent().getCategory().contains("authentication");
                    EntityRelationType relType = isAuth ? EntityRelationType.USER_AUTHENTICATED_TO : EntityRelationType.HOST_HAS_USER;
                    resolutionService.recordRelationship(
                            userEntity.getCanonicalId(),
                            hostEntity.getCanonicalId(),
                            relType,
                            1.0,
                            "User observed on host in event " + eventId,
                            "TELEMETRY_EVENT"
                    );
                }
            }

            // 3. Process Extraction
            if (event.getProcess() != null && event.getProcess().getName() != null && !event.getProcess().getName().trim().isEmpty()) {
                String procName = event.getProcess().getName();
                Long pid = event.getProcess().getPid() != null && event.getProcess().getPid() > 0 ? (long) event.getProcess().getPid() : null;
                String procCanonicalId = resolutionService.buildProcessCanonicalId(hostname, procName, pid);

                Map<String, Object> procAttrs = new HashMap<>();
                if (event.getProcess().getExecutable() != null) procAttrs.put("executable", event.getProcess().getExecutable());
                if (event.getProcess().getCommandLine() != null) procAttrs.put("command_line", event.getProcess().getCommandLine());
                if (pid != null) procAttrs.put("pid", pid);

                processEntity = resolutionService.resolveOrCreateEntity(EntityType.PROCESS, procCanonicalId, procName, procAttrs, 0.0);
                resolutionService.recordObservation(processEntity, "TELEMETRY_EVENT", eventId, hostname, rawRef, procAttrs, 1.0, eventTime);
                extracted.add(processEntity);

                // Relationship: HOST_HAS_PROCESS
                if (hostEntity != null) {
                    resolutionService.recordRelationship(
                            hostEntity.getCanonicalId(),
                            processEntity.getCanonicalId(),
                            EntityRelationType.HOST_HAS_PROCESS,
                            1.0,
                            "Process execution observed on host",
                            "TELEMETRY_EVENT"
                    );
                }

                // Relationship: PROCESS_SPAWNED_PROCESS (if parent process known)
                if (event.getProcess().getParent() != null && event.getProcess().getParent().getName() != null
                        && !event.getProcess().getParent().getName().trim().isEmpty()) {
                    String parentName = event.getProcess().getParent().getName();
                    Long ppid = event.getProcess().getParent().getPid() != null && event.getProcess().getParent().getPid() > 0
                            ? event.getProcess().getParent().getPid() : null;
                    String parentCanonicalId = resolutionService.buildProcessCanonicalId(hostname, parentName, ppid);

                    EntityRecord parentProc = resolutionService.resolveOrCreateEntity(EntityType.PROCESS, parentCanonicalId, parentName, Map.of("role", "parent"), 0.0);
                    resolutionService.recordRelationship(
                            parentProc.getCanonicalId(),
                            processEntity.getCanonicalId(),
                            EntityRelationType.PROCESS_SPAWNED_PROCESS,
                            0.95,
                            "Parent-child process execution lineage",
                            "TELEMETRY_EVENT"
                    );
                }
            }

            // 4. Source IP Extraction
            if (event.getSource() != null && event.getSource().getIp() != null && !event.getSource().getIp().trim().isEmpty()) {
                String srcIp = event.getSource().getIp();
                String ipCanonicalId = resolutionService.buildIpCanonicalId(srcIp);
                srcIpEntity = resolutionService.resolveOrCreateEntity(EntityType.IP_ADDRESS, ipCanonicalId, srcIp, Map.of("direction", "source"), 0.0);
                resolutionService.recordObservation(srcIpEntity, "TELEMETRY_EVENT", eventId, hostname, rawRef, Map.of("ip", srcIp), 1.0, eventTime);
                extracted.add(srcIpEntity);

                if (hostEntity != null) {
                    resolutionService.recordRelationship(hostEntity.getCanonicalId(), srcIpEntity.getCanonicalId(),
                            EntityRelationType.ENTITY_RESOLVED_TO_IP, 0.9, "Host network interface IP association", "TELEMETRY_EVENT");
                }
            }

            // 5. Destination IP Extraction
            if (event.getDestination() != null && event.getDestination().getIp() != null && !event.getDestination().getIp().trim().isEmpty()) {
                String destIp = event.getDestination().getIp();
                String ipCanonicalId = resolutionService.buildIpCanonicalId(destIp);
                destIpEntity = resolutionService.resolveOrCreateEntity(EntityType.IP_ADDRESS, ipCanonicalId, destIp, Map.of("direction", "destination"), 0.0);
                resolutionService.recordObservation(destIpEntity, "TELEMETRY_EVENT", eventId, hostname, rawRef, Map.of("ip", destIp), 1.0, eventTime);
                extracted.add(destIpEntity);

                // Relationship: PROCESS_CONNECTED_TO (Process connecting to destination IP)
                if (processEntity != null) {
                    resolutionService.recordRelationship(
                            processEntity.getCanonicalId(),
                            destIpEntity.getCanonicalId(),
                            EntityRelationType.PROCESS_CONNECTED_TO,
                            0.95,
                            "Process established network connection to IP",
                            "TELEMETRY_EVENT"
                    );
                }
            }

            // 6. Domain Extraction
            String domain = null;
            if (event.getDestination() != null && event.getDestination().getDomain() != null) {
                domain = event.getDestination().getDomain();
            } else if (event.getSource() != null && event.getSource().getDomain() != null) {
                domain = event.getSource().getDomain();
            }

            if (domain != null && !domain.trim().isEmpty()) {
                String domainCanonicalId = resolutionService.buildDomainCanonicalId(domain);
                domainEntity = resolutionService.resolveOrCreateEntity(EntityType.DOMAIN, domainCanonicalId, domain, Map.of("domain", domain), 0.0);
                resolutionService.recordObservation(domainEntity, "TELEMETRY_EVENT", eventId, hostname, rawRef, Map.of("domain", domain), 1.0, eventTime);
                extracted.add(domainEntity);

                if (destIpEntity != null) {
                    resolutionService.recordRelationship(domainEntity.getCanonicalId(), destIpEntity.getCanonicalId(),
                            EntityRelationType.ENTITY_RESOLVED_TO_IP, 0.85, "DNS resolution / socket connection mapping", "TELEMETRY_EVENT");
                }
            }

            // 7. File & Hash Extraction
            if (event.getFile() != null) {
                String filePath = event.getFile().getPath() != null ? event.getFile().getPath() : event.getFile().getName();
                if (filePath != null && !filePath.trim().isEmpty()) {
                    String fileCanonicalId = resolutionService.buildFileCanonicalId(hostname, filePath);
                    Map<String, Object> fileAttrs = new HashMap<>();
                    if (event.getFile().getName() != null) fileAttrs.put("name", event.getFile().getName());
                    if (event.getFile().getSize() > 0) fileAttrs.put("size", event.getFile().getSize());

                    fileEntity = resolutionService.resolveOrCreateEntity(EntityType.FILE, fileCanonicalId, filePath, fileAttrs, 0.0);
                    resolutionService.recordObservation(fileEntity, "TELEMETRY_EVENT", eventId, hostname, rawRef, fileAttrs, 1.0, eventTime);
                    extracted.add(fileEntity);

                    if (hostEntity != null) {
                        resolutionService.recordRelationship(hostEntity.getCanonicalId(), fileEntity.getCanonicalId(),
                                EntityRelationType.FILE_OBSERVED_ON, 1.0, "File resident or modified on host", "TELEMETRY_EVENT");
                    }
                }

                // File Hash
                String hashSha256 = event.getFile().getHashSha256();
                if (hashSha256 != null && !hashSha256.trim().isEmpty()) {
                    String hashCanonicalId = resolutionService.buildHashCanonicalId("sha256", hashSha256);
                    hashEntity = resolutionService.resolveOrCreateEntity(EntityType.HASH, hashCanonicalId, hashSha256, Map.of("algorithm", "SHA-256"), 0.0);
                    resolutionService.recordObservation(hashEntity, "TELEMETRY_EVENT", eventId, hostname, rawRef, Map.of("sha256", hashSha256), 1.0, eventTime);
                    extracted.add(hashEntity);
                }
            }

        } catch (Exception e) {
            log.error("Defensive isolation: Entity extraction failed for event: {}", e.getMessage(), e);
        }

        return extracted;
    }

    /**
     * Extracts canonical entities, increments risk, and establishes finding association relationships from a generated FindingDto.
     */
    @Transactional
    public void extractFromFinding(FindingDto finding) {
        if (finding == null) return;

        try {
            double riskIncrement = switch (finding.getRuleSeverity() != null ? finding.getRuleSeverity().toUpperCase() : "MEDIUM") {
                case "CRITICAL" -> 30.0;
                case "HIGH" -> 20.0;
                case "MEDIUM" -> 10.0;
                default -> 5.0;
            };

            // Associate Host Entity
            String hostname = finding.getAssetName() != null ? finding.getAssetName() : finding.getAssetId();
            EntityRecord hostEntity = null;
            if (hostname != null && !hostname.trim().isEmpty()) {
                String hostCanonicalId = resolutionService.buildHostCanonicalId(hostname);
                hostEntity = resolutionService.resolveOrCreateEntity(EntityType.HOST, hostCanonicalId, hostname,
                        Map.of("last_alert_rule", finding.getRuleId(), "mitre_tactic", finding.getMitreTactic() != null ? finding.getMitreTactic() : "UNKNOWN"),
                        riskIncrement);

                resolutionService.recordObservation(hostEntity, "FINDING", finding.getFindingId(), hostname,
                        finding.getRuleId() + ":" + finding.getRuleName(), Map.of("severity", finding.getRuleSeverity()), 1.0,
                        finding.getTimestamp() != null ? finding.getTimestamp() : Instant.now());
            }

            // Inspect finding details for User, IP, Hash
            if (finding.getDetails() != null) {
                // User from details
                Object userObj = finding.getDetails().get("user.name");
                if (userObj instanceof String u && !u.trim().isEmpty()) {
                    String userCanonicalId = resolutionService.buildUserCanonicalId(u);
                    EntityRecord userEntity = resolutionService.resolveOrCreateEntity(EntityType.USER, userCanonicalId, u,
                            Map.of("last_alert_rule", finding.getRuleId()), riskIncrement);

                    resolutionService.recordObservation(userEntity, "FINDING", finding.getFindingId(), hostname,
                            finding.getRuleId(), Map.of("severity", finding.getRuleSeverity()), 1.0, finding.getTimestamp());

                    if (hostEntity != null) {
                        resolutionService.recordRelationship(userEntity.getCanonicalId(), hostEntity.getCanonicalId(),
                                EntityRelationType.ENTITY_ASSOCIATED_WITH_FINDING, 0.95,
                                "User involved in security finding " + finding.getFindingId(), "FINDING");
                    }
                }

                // Source IP from details
                Object ipObj = finding.getDetails().get("source.ip");
                if (ipObj instanceof String ip && !ip.trim().isEmpty()) {
                    String ipCanonicalId = resolutionService.buildIpCanonicalId(ip);
                    EntityRecord ipEntity = resolutionService.resolveOrCreateEntity(EntityType.IP_ADDRESS, ipCanonicalId, ip,
                            Map.of("last_alert_rule", finding.getRuleId()), riskIncrement);

                    resolutionService.recordObservation(ipEntity, "FINDING", finding.getFindingId(), hostname,
                            finding.getRuleId(), Map.of("severity", finding.getRuleSeverity()), 1.0, finding.getTimestamp());

                    if (hostEntity != null) {
                        resolutionService.recordRelationship(ipEntity.getCanonicalId(), hostEntity.getCanonicalId(),
                                EntityRelationType.ENTITY_ASSOCIATED_WITH_FINDING, 0.95,
                                "IP involved in security finding " + finding.getFindingId(), "FINDING");
                    }
                }

                // File Hash from details
                Object hashObj = finding.getDetails().get("file.hash.sha256");
                if (hashObj instanceof String h && !h.trim().isEmpty()) {
                    String hashCanonicalId = resolutionService.buildHashCanonicalId("sha256", h);
                    EntityRecord hashEntity = resolutionService.resolveOrCreateEntity(EntityType.HASH, hashCanonicalId, h,
                            Map.of("last_alert_rule", finding.getRuleId()), riskIncrement);

                    resolutionService.recordObservation(hashEntity, "FINDING", finding.getFindingId(), hostname,
                            finding.getRuleId(), Map.of("severity", finding.getRuleSeverity()), 1.0, finding.getTimestamp());

                    if (hostEntity != null) {
                        resolutionService.recordRelationship(hashEntity.getCanonicalId(), hostEntity.getCanonicalId(),
                                EntityRelationType.ENTITY_ASSOCIATED_WITH_FINDING, 0.95,
                                "Malicious hash involved in security finding " + finding.getFindingId(), "FINDING");
                    }
                }
            }

        } catch (Exception e) {
            log.error("Defensive isolation: Entity extraction from finding failed: {}", e.getMessage(), e);
        }
    }
}
