package com.blueops.telemetry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class EventNormalizationService {

    private static final Logger log = LoggerFactory.getLogger(EventNormalizationService.class);

    private final AtomicLong totalReceived = new AtomicLong(0);
    private final AtomicLong totalNormalized = new AtomicLong(0);
    private final AtomicLong totalFailedDlq = new AtomicLong(0);

    // Bounded in-memory store for recent telemetry events (holds last 1000 events)
    private static final int MAX_BUFFER_SIZE = 1000;
    private final Deque<NormalizedEvent> recentEvents = new ConcurrentLinkedDeque<>();
    private final List<Map<String, Object>> deadLetterQueue = Collections.synchronizedList(new ArrayList<>());

    public NormalizedEvent normalize(Map<String, Object> raw) {
        totalReceived.incrementAndGet();
        try {
            NormalizedEvent event = new NormalizedEvent();
            String eventId = (String) raw.getOrDefault("id", UUID.randomUUID().toString());
            event.setId(eventId);

            // Determine provider / source
            String provider = (String) raw.getOrDefault("provider", "Unknown");
            if (raw.containsKey("EventID") || raw.containsKey("Sysmon")) {
                provider = "Sysmon";
            } else if (raw.containsKey("audit_type") || raw.containsKey("auditd") || raw.containsKey("SYSCALL")) {
                provider = "Linux-auditd";
            } else if (raw.containsKey("event_type") || raw.containsKey("suricata")) {
                provider = "Suricata";
            }

            // Timestamp parsing
            Instant eventTime = Instant.now();
            if (raw.containsKey("@timestamp")) {
                try {
                    eventTime = Instant.parse(raw.get("@timestamp").toString());
                } catch (Exception ignored) {}
            }
            event.setTimestamp(eventTime);

            // Event Metadata
            String action = (String) raw.getOrDefault("action", "unknown_action");
            int severity = raw.containsKey("severity") ? Integer.parseInt(raw.get("severity").toString()) : 1;
            event.setEvent(new NormalizedEvent.EventMetadata(
                    eventId, provider, provider.toLowerCase() + ".security",
                    List.of(extractCategory(raw, provider)),
                    List.of("activity"), action, severity, raw.toString()
            ));

            // Host Metadata
            String hostname = (String) raw.getOrDefault("hostname", raw.getOrDefault("host", "LAB-UNKNOWN"));
            String hostIp = (String) raw.getOrDefault("host_ip", "192.168.56.101");
            String os = hostname.contains("WIN") ? "Windows" : (hostname.contains("FW") ? "FreeBSD" : "Linux");
            String persistentId = hostname.contains("WIN") ? "WIN-ASSET-001" : (hostname.contains("LNX") ? "LNX-ASSET-001" : "NET-ASSET-001");
            event.setHost(new NormalizedEvent.HostMetadata(persistentId, hostname, hostIp, os, "2026.1"));

            // User Metadata
            String username = (String) raw.getOrDefault("username", raw.getOrDefault("user", "SYSTEM"));
            event.setUser(new NormalizedEvent.UserMetadata(username, "S-1-" + Math.abs(username.hashCode()), "BLUEOPS-LAB"));

            // Process Metadata
            if (raw.containsKey("process_name") || raw.containsKey("Image") || raw.containsKey("command_line") || raw.containsKey("CommandLine")) {
                String procPath = (String) raw.getOrDefault("executable", raw.getOrDefault("Image", "unknown.exe"));
                String procName = (String) raw.getOrDefault("process_name", extractFileName(procPath));
                String cmdLine = (String) raw.getOrDefault("command_line", raw.getOrDefault("CommandLine", ""));
                String procHash = (String) raw.getOrDefault("hash", raw.getOrDefault("sha256", ""));
                Long pid = raw.containsKey("pid") ? Long.parseLong(raw.get("pid").toString()) : 1000L;

                NormalizedEvent.ProcessParent parent = null;
                if (raw.containsKey("parent_process") || raw.containsKey("ParentImage")) {
                    String parentPath = (String) raw.getOrDefault("parent_executable", raw.getOrDefault("ParentImage", "explorer.exe"));
                    String parentName = (String) raw.getOrDefault("parent_process", extractFileName(parentPath));
                    parent = new NormalizedEvent.ProcessParent(900L, parentName, parentPath, (String) raw.getOrDefault("ParentCommandLine", ""));
                }
                event.setProcess(new NormalizedEvent.ProcessMetadata(pid, procName, procPath, cmdLine, procHash, parent));
            }

            // Network Metadata
            if (raw.containsKey("dest_ip") || raw.containsKey("destination_ip") || raw.containsKey("DestinationIp") || raw.containsKey("src_ip") || raw.containsKey("source_ip")) {
                String srcIp = (String) raw.getOrDefault("src_ip", raw.getOrDefault("source_ip", raw.getOrDefault("SourceIp", "192.168.56.101")));
                Integer srcPort = raw.containsKey("src_port") ? Integer.parseInt(raw.get("src_port").toString()) : 49152;
                String dstIp = (String) raw.getOrDefault("dest_ip", raw.getOrDefault("destination_ip", raw.getOrDefault("DestinationIp", "198.51.100.24")));
                Integer dstPort = raw.containsKey("dest_port") ? Integer.parseInt(raw.get("dest_port").toString()) : 443;
                String domain = (String) raw.getOrDefault("domain", raw.getOrDefault("dns_query", ""));

                event.setSource(new NormalizedEvent.NetworkEndpoint(srcIp, srcPort, null));
                event.setDestination(new NormalizedEvent.NetworkEndpoint(dstIp, dstPort, domain));
                event.setNetwork(new NormalizedEvent.NetworkMetadata("TCP", "IP", "outbound", "1:lab-comm-id"));
            }

            // File Metadata
            if (raw.containsKey("file_path") || raw.containsKey("TargetFilename")) {
                String path = (String) raw.getOrDefault("file_path", raw.getOrDefault("TargetFilename", ""));
                event.setFile(new NormalizedEvent.FileMetadata(path, extractFileName(path), 1024L, (String) raw.getOrDefault("hash", "")));
            }

            // Registry Metadata
            if (raw.containsKey("TargetObject") || raw.containsKey("registry_path")) {
                String regPath = (String) raw.getOrDefault("TargetObject", raw.getOrDefault("registry_path", ""));
                event.setRegistry(new NormalizedEvent.RegistryMetadata(regPath, "ValueName", "PayloadData"));
            }

            // BlueOps Metadata
            event.setBlueops(new NormalizedEvent.BlueOpsMetadata("1.0.0", Instant.now(), "fluent-bit", "success"));

            // Maintain bounded deque
            while (recentEvents.size() >= MAX_BUFFER_SIZE) {
                recentEvents.pollLast();
            }
            recentEvents.addFirst(event);
            totalNormalized.incrementAndGet();

            return event;
        } catch (Exception ex) {
            totalFailedDlq.incrementAndGet();
            log.warn("Telemetry normalization failed. Routing to Dead-Letter Queue (DLQ): {}", ex.getMessage());
            Map<String, Object> dlqEntry = new HashMap<>(raw);
            dlqEntry.put("dlq_error", ex.getMessage());
            dlqEntry.put("dlq_timestamp", Instant.now().toString());
            deadLetterQueue.add(dlqEntry);
            return null;
        }
    }

    public List<NormalizedEvent> getRecentEvents(int limit) {
        List<NormalizedEvent> list = new ArrayList<>(recentEvents);
        if (list.size() > limit) {
            return list.subList(0, limit);
        }
        return list;
    }

    public Map<String, Object> getTelemetryStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalReceived", totalReceived.get());
        stats.put("totalNormalized", totalNormalized.get());
        stats.put("totalFailedDlq", totalFailedDlq.get());
        stats.put("bufferedCount", recentEvents.size());
        stats.put("dlqCount", deadLetterQueue.size());
        return stats;
    }

    private String extractCategory(Map<String, Object> raw, String provider) {
        if ("Sysmon".equals(provider)) {
            Object eventId = raw.getOrDefault("EventID", raw.get("event_id"));
            if (eventId != null && ("1".equals(eventId.toString()) || "5".equals(eventId.toString()))) return "process";
            if (eventId != null && "3".equals(eventId.toString())) return "network";
            if (eventId != null && "11".equals(eventId.toString())) return "file";
            if (eventId != null && ("12".equals(eventId.toString()) || "13".equals(eventId.toString()))) return "registry";
            if (eventId != null && "22".equals(eventId.toString())) return "dns";
        }
        if (raw.containsKey("process_name") || raw.containsKey("CommandLine")) return "process";
        if (raw.containsKey("dest_ip") || raw.containsKey("dns_query")) return "network";
        return "security";
    }

    private String extractFileName(String path) {
        if (path == null || path.isEmpty()) return "";
        int idx = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        return idx >= 0 ? path.substring(idx + 1) : path;
    }
}
