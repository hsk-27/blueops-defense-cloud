package com.blueops.telemetry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class EventNormalizationService {

    private static final Logger log = LoggerFactory.getLogger(EventNormalizationService.class);

    private static final DateTimeFormatter SYSMON_UTC_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss[.SSS]")
            .withZone(ZoneOffset.UTC);

    private final AtomicLong totalReceived = new AtomicLong(0);
    private final AtomicLong totalNormalized = new AtomicLong(0);
    private final AtomicLong totalFailedDlq = new AtomicLong(0);
    private final AtomicLong totalQuarantined = new AtomicLong(0);

    // Bounded in-memory store for recent telemetry events (holds last 1000 events)
    private static final int MAX_BUFFER_SIZE = 1000;
    private static final int MAX_DLQ_SIZE = 500;
    private static final int MAX_POISON_PILL_SIZE = 200;
    private final Deque<NormalizedEvent> recentEvents = new ConcurrentLinkedDeque<>();
    private final List<Map<String, Object>> deadLetterQueue = Collections.synchronizedList(new ArrayList<>());
    private final List<Map<String, Object>> poisonPillQueue = Collections.synchronizedList(new ArrayList<>());

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
            Instant eventTime = parseTimestamp(raw);
            event.setTimestamp(eventTime);

            // Event Metadata
            String action = (String) raw.getOrDefault("action", "unknown_action");
            int severity = parseSeverity(raw);
            List<String> eventTypes = new ArrayList<>();
            eventTypes.add("activity");
            if (raw.containsKey("outcome")) {
                eventTypes.add(String.valueOf(raw.get("outcome")));
            }
            event.setEvent(new NormalizedEvent.EventMetadata(
                    eventId, provider, provider.toLowerCase() + ".security",
                    List.of(extractCategory(raw, provider)),
                    eventTypes, action, severity, raw.toString()
            ));

            // Host Metadata
            String hostname = extractFirstString(raw, List.of("hostname", "host", "HostName", "Computer", "ComputerName"), "LAB-UNKNOWN");
            String hostIp = extractFirstString(raw, List.of("host_ip", "hostIp", "HostIp", "ip"), "192.168.56.101");
            String os = hostname.contains("WIN") ? "Windows" : (hostname.contains("FW") ? "FreeBSD" : "Linux");
            String persistentId = hostname.contains("WIN") ? "WIN-ASSET-001" : (hostname.contains("LNX") ? "LNX-ASSET-001" : "NET-ASSET-001");
            event.setHost(new NormalizedEvent.HostMetadata(persistentId, hostname, hostIp, os, "2026.1"));

            // User Metadata
            String username = extractFirstString(raw, List.of("username", "user", "User", "UserName"), "SYSTEM");
            event.setUser(new NormalizedEvent.UserMetadata(username, "S-1-" + Math.abs(username.hashCode()), "BLUEOPS-LAB"));

            // Process Metadata
            if (raw.containsKey("process_name") || raw.containsKey("Image") || raw.containsKey("command_line") || raw.containsKey("CommandLine") || raw.containsKey("executable")) {
                String procPath = extractFirstString(raw, List.of("executable", "Image", "process_path"), "unknown.exe");
                String procName = extractFirstString(raw, List.of("process_name", "ProcessName"), extractFileName(procPath));
                String cmdLine = extractFirstString(raw, List.of("command_line", "CommandLine", "cmdline"), "");
                String procHash = extractFirstString(raw, List.of("hash", "sha256", "Hashes"), "");
                Long pid = parseLongSafe(raw.getOrDefault("pid", raw.get("ProcessId")), 1000L);

                NormalizedEvent.ProcessParent parent = null;
                if (raw.containsKey("parent_process") || raw.containsKey("ParentImage") || raw.containsKey("parent_executable")) {
                    String parentPath = extractFirstString(raw, List.of("parent_executable", "ParentImage"), "explorer.exe");
                    String parentName = extractFirstString(raw, List.of("parent_process", "ParentProcessName"), extractFileName(parentPath));
                    parent = new NormalizedEvent.ProcessParent(900L, parentName, parentPath, extractFirstString(raw, List.of("ParentCommandLine", "parent_command_line"), ""));
                }
                event.setProcess(new NormalizedEvent.ProcessMetadata(pid, procName, procPath, cmdLine, procHash, parent));
            }

            // Network Metadata
            boolean hasNetwork = raw.containsKey("dest_ip") || raw.containsKey("destination_ip") ||
                    raw.containsKey("DestinationIp") || raw.containsKey("src_ip") ||
                    raw.containsKey("source_ip") || raw.containsKey("SourceIp") ||
                    raw.containsKey("dst_ip") || raw.containsKey("dest_port") ||
                    raw.containsKey("destination_port") || raw.containsKey("DestinationPort") ||
                    raw.containsKey("dport") || raw.containsKey("dns_query") || raw.containsKey("domain");

            if (hasNetwork) {
                String srcIp = extractFirstString(raw, List.of("src_ip", "source_ip", "SourceIp", "src", "client_ip"), "192.168.56.101");
                Integer srcPort = parsePort(raw, List.of("src_port", "source_port", "SourcePort", "sport"), 49152);
                String dstIp = extractFirstString(raw, List.of("dest_ip", "destination_ip", "DestinationIp", "dst_ip", "dest", "server_ip"), "198.51.100.24");
                Integer dstPort = parsePort(raw, List.of("dest_port", "destination_port", "DestinationPort", "dport"), 443);
                String domain = extractFirstString(raw, List.of("domain", "dns_query", "QueryName"), "");

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
            dlqEntry.put("dlq_error", ex.getMessage() != null ? ex.getMessage() : "Unknown normalization error");
            dlqEntry.put("dlq_timestamp", Instant.now().toString());

            int replayCount = 0;
            if (raw.containsKey("dlq_replay_count")) {
                Object rc = raw.get("dlq_replay_count");
                if (rc instanceof Number n) replayCount = n.intValue();
            }
            dlqEntry.put("dlq_replay_count", replayCount);

            synchronized (deadLetterQueue) {
                while (deadLetterQueue.size() >= MAX_DLQ_SIZE) {
                    deadLetterQueue.remove(0);
                }
                deadLetterQueue.add(dlqEntry);
            }
            return null;
        }
    }

    public void quarantinePoisonPill(Map<String, Object> entry) {
        totalQuarantined.incrementAndGet();
        log.warn("Poison pill detected after repeated DLQ replay failures. Quarantining payload id={}", entry.get("id"));
        synchronized (poisonPillQueue) {
            while (poisonPillQueue.size() >= MAX_POISON_PILL_SIZE) {
                poisonPillQueue.remove(0);
            }
            poisonPillQueue.add(entry);
        }
    }

    public List<Map<String, Object>> getPoisonPillQueue(int limit) {
        synchronized (poisonPillQueue) {
            List<Map<String, Object>> list = new ArrayList<>(poisonPillQueue);
            int safeLimit = Math.min(Math.max(0, limit), list.size());
            return list.subList(0, safeLimit);
        }
    }

    public Optional<NormalizedEvent> getEventById(String eventId) {
        if (eventId == null || eventId.isBlank()) return Optional.empty();
        for (NormalizedEvent evt : recentEvents) {
            if (eventId.equalsIgnoreCase(evt.getId())) {
                return Optional.of(evt);
            }
        }
        return Optional.empty();
    }

    public List<NormalizedEvent> searchEvents(String query, String provider, String host, String category, int limit) {
        int safeLimit = limit <= 0 ? 50 : Math.min(limit, 200);
        String qClean = query != null ? query.trim().toLowerCase(Locale.ROOT) : null;
        String pClean = provider != null ? provider.trim().toLowerCase(Locale.ROOT) : null;
        String hClean = host != null ? host.trim().toLowerCase(Locale.ROOT) : null;
        String cClean = category != null ? category.trim().toLowerCase(Locale.ROOT) : null;

        List<NormalizedEvent> results = new ArrayList<>();
        for (NormalizedEvent evt : recentEvents) {
            if (results.size() >= safeLimit) break;

            if (pClean != null && (evt.getEvent() == null || evt.getEvent().getProvider() == null
                    || !evt.getEvent().getProvider().toLowerCase(Locale.ROOT).contains(pClean))) {
                continue;
            }

            if (hClean != null && (evt.getHost() == null || evt.getHost().getName() == null
                    || !evt.getHost().getName().toLowerCase(Locale.ROOT).contains(hClean))) {
                continue;
            }

            if (cClean != null && (evt.getEvent() == null || evt.getEvent().getCategory() == null
                    || evt.getEvent().getCategory().stream().noneMatch(c -> c.toLowerCase(Locale.ROOT).contains(cClean)))) {
                continue;
            }

            if (qClean != null) {
                boolean matchesQuery = false;
                if (evt.getEvent() != null && evt.getEvent().getOriginal() != null
                        && evt.getEvent().getOriginal().toLowerCase(Locale.ROOT).contains(qClean)) {
                    matchesQuery = true;
                } else if (evt.getProcess() != null && evt.getProcess().getCommandLine() != null
                        && evt.getProcess().getCommandLine().toLowerCase(Locale.ROOT).contains(qClean)) {
                    matchesQuery = true;
                } else if (evt.getUser() != null && evt.getUser().getName() != null
                        && evt.getUser().getName().toLowerCase(Locale.ROOT).contains(qClean)) {
                    matchesQuery = true;
                }
                if (!matchesQuery) continue;
            }

            results.add(evt);
        }
        return results;
    }

    public List<NormalizedEvent> getRecentEvents(int limit) {
        if (limit <= 0) {
            return Collections.emptyList();
        }
        List<NormalizedEvent> list = new ArrayList<>(recentEvents);
        int safeLimit = Math.min(limit, list.size());
        return list.subList(0, safeLimit);
    }

    public List<Map<String, Object>> getDeadLetterQueue(int limit) {
        if (limit <= 0) {
            return Collections.emptyList();
        }
        synchronized (deadLetterQueue) {
            List<Map<String, Object>> list = new ArrayList<>(deadLetterQueue);
            int safeLimit = Math.min(limit, list.size());
            return list.subList(0, safeLimit);
        }
    }

    public int clearDeadLetterQueue() {
        synchronized (deadLetterQueue) {
            int count = deadLetterQueue.size();
            deadLetterQueue.clear();
            return count;
        }
    }

    public Object getDeadLetterQueueLock() {
        return deadLetterQueue;
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

    private Instant parseTimestamp(Map<String, Object> raw) {
        Object val = raw.getOrDefault("@timestamp",
                raw.getOrDefault("timestamp",
                raw.getOrDefault("time",
                raw.getOrDefault("UtcTime",
                raw.get("event_time")))));

        if (val == null) {
            return Instant.now();
        }

        String str = val.toString().trim();
        if (str.isEmpty()) {
            return Instant.now();
        }

        try {
            return Instant.parse(str);
        } catch (Exception ignored) {}

        try {
            return SYSMON_UTC_FORMAT.parse(str, Instant::from);
        } catch (Exception ignored) {}

        try {
            long num = Long.parseLong(str);
            if (num > 100000000000L) {
                return Instant.ofEpochMilli(num);
            } else if (num > 0) {
                return Instant.ofEpochSecond(num);
            }
        } catch (Exception ignored) {}

        return Instant.now();
    }

    private int parseSeverity(Map<String, Object> raw) {
        if (!raw.containsKey("severity") || raw.get("severity") == null) return 1;
        try {
            return Integer.parseInt(raw.get("severity").toString().trim());
        } catch (Exception ignored) {
            return 1;
        }
    }

    private Integer parsePort(Map<String, Object> raw, List<String> candidateKeys, int defaultPort) {
        for (String k : candidateKeys) {
            if (raw.containsKey(k) && raw.get(k) != null) {
                try {
                    String str = raw.get(k).toString().trim();
                    if (!str.isEmpty()) {
                        int p = Integer.parseInt(str);
                        if (p >= 0 && p <= 65535) {
                            return p;
                        }
                    }
                } catch (Exception ignored) {}
            }
        }
        return defaultPort;
    }

    private Long parseLongSafe(Object obj, Long defaultVal) {
        if (obj == null) return defaultVal;
        try {
            String str = obj.toString().trim();
            return str.isEmpty() ? defaultVal : Long.parseLong(str);
        } catch (Exception ignored) {
            return defaultVal;
        }
    }

    private String extractFirstString(Map<String, Object> raw, List<String> candidateKeys, String defaultVal) {
        for (String k : candidateKeys) {
            if (raw.containsKey(k) && raw.get(k) != null) {
                String str = raw.get(k).toString().trim();
                if (!str.isEmpty()) {
                    return str;
                }
            }
        }
        return defaultVal;
    }
}
