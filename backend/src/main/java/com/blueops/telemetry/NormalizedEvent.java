package com.blueops.telemetry;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class NormalizedEvent {
    private String id;
    private Instant timestamp;
    private EventMetadata event;
    private HostMetadata host;
    private UserMetadata user;
    private ProcessMetadata process;
    private NetworkEndpoint source;
    private NetworkEndpoint destination;
    private NetworkMetadata network;
    private FileMetadata file;
    private RegistryMetadata registry;
    private List<String> relatedIps;
    private List<String> relatedUsers;
    private List<String> relatedHashes;
    private BlueOpsMetadata blueops;

    public NormalizedEvent() {
        this.timestamp = Instant.now();
    }

    public static class EventMetadata {
        private String id;
        private String provider;
        private String dataset;
        private List<String> category;
        private List<String> type;
        private String action;
        private int severity;
        private String original;

        public EventMetadata() {}
        public EventMetadata(String id, String provider, String dataset, List<String> category, List<String> type, String action, int severity, String original) {
            this.id = id; this.provider = provider; this.dataset = dataset;
            this.category = category; this.type = type; this.action = action;
            this.severity = severity; this.original = original;
        }

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }
        public String getDataset() { return dataset; }
        public void setDataset(String dataset) { this.dataset = dataset; }
        public List<String> getCategory() { return category; }
        public void setCategory(List<String> category) { this.category = category; }
        public List<String> getType() { return type; }
        public void setType(List<String> type) { this.type = type; }
        public String getAction() { return action; }
        public void setAction(String action) { this.action = action; }
        public int getSeverity() { return severity; }
        public void setSeverity(int severity) { this.severity = severity; }
        public String getOriginal() { return original; }
        public void setOriginal(String original) { this.original = original; }
    }

    public static class HostMetadata {
        private String id;
        private String name;
        private String ip;
        private String osName;
        private String osVersion;

        public HostMetadata() {}
        public HostMetadata(String id, String name, String ip, String osName, String osVersion) {
            this.id = id; this.name = name; this.ip = ip; this.osName = osName; this.osVersion = osVersion;
        }

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getIp() { return ip; }
        public void setIp(String ip) { this.ip = ip; }
        public String getOsName() { return osName; }
        public void setOsName(String osName) { this.osName = osName; }
        public String getOsVersion() { return osVersion; }
        public void setOsVersion(String osVersion) { this.osVersion = osVersion; }
    }

    public static class UserMetadata {
        private String name;
        private String id;
        private String domain;

        public UserMetadata() {}
        public UserMetadata(String name, String id, String domain) {
            this.name = name; this.id = id; this.domain = domain;
        }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
    }

    public static class ProcessMetadata {
        private Long pid;
        private String name;
        private String executable;
        private String commandLine;
        private String hashSha256;
        private ProcessParent parent;

        public ProcessMetadata() {}
        public ProcessMetadata(Long pid, String name, String executable, String commandLine, String hashSha256, ProcessParent parent) {
            this.pid = pid; this.name = name; this.executable = executable;
            this.commandLine = commandLine; this.hashSha256 = hashSha256; this.parent = parent;
        }

        public Long getPid() { return pid; }
        public void setPid(Long pid) { this.pid = pid; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getExecutable() { return executable; }
        public void setExecutable(String executable) { this.executable = executable; }
        public String getCommandLine() { return commandLine; }
        public void setCommandLine(String commandLine) { this.commandLine = commandLine; }
        public String getHashSha256() { return hashSha256; }
        public void setHashSha256(String hashSha256) { this.hashSha256 = hashSha256; }
        public ProcessParent getParent() { return parent; }
        public void setParent(ProcessParent parent) { this.parent = parent; }
    }

    public static class ProcessParent {
        private Long pid;
        private String name;
        private String executable;
        private String commandLine;

        public ProcessParent() {}
        public ProcessParent(Long pid, String name, String executable, String commandLine) {
            this.pid = pid; this.name = name; this.executable = executable; this.commandLine = commandLine;
        }

        public Long getPid() { return pid; }
        public void setPid(Long pid) { this.pid = pid; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getExecutable() { return executable; }
        public void setExecutable(String executable) { this.executable = executable; }
        public String getCommandLine() { return commandLine; }
        public void setCommandLine(String commandLine) { this.commandLine = commandLine; }
    }

    public static class NetworkEndpoint {
        private String ip;
        private Integer port;
        private String domain;

        public NetworkEndpoint() {}
        public NetworkEndpoint(String ip, Integer port, String domain) {
            this.ip = ip; this.port = port; this.domain = domain;
        }

        public String getIp() { return ip; }
        public void setIp(String ip) { this.ip = ip; }
        public Integer getPort() { return port; }
        public void setPort(Integer port) { this.port = port; }
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
    }

    public static class NetworkMetadata {
        private String transport;
        private String protocol;
        private String direction;
        private String communityId;

        public NetworkMetadata() {}
        public NetworkMetadata(String transport, String protocol, String direction, String communityId) {
            this.transport = transport; this.protocol = protocol; this.direction = direction; this.communityId = communityId;
        }

        public String getTransport() { return transport; }
        public void setTransport(String transport) { this.transport = transport; }
        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }
        public String getDirection() { return direction; }
        public void setDirection(String direction) { this.direction = direction; }
        public String getCommunityId() { return communityId; }
        public void setCommunityId(String communityId) { this.communityId = communityId; }
    }

    public static class FileMetadata {
        private String path;
        private String name;
        private Long size;
        private String hashSha256;

        public FileMetadata() {}
        public FileMetadata(String path, String name, Long size, String hashSha256) {
            this.path = path; this.name = name; this.size = size; this.hashSha256 = hashSha256;
        }

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public Long getSize() { return size; }
        public void setSize(Long size) { this.size = size; }
        public String getHashSha256() { return hashSha256; }
        public void setHashSha256(String hashSha256) { this.hashSha256 = hashSha256; }
    }

    public static class RegistryMetadata {
        private String path;
        private String key;
        private String value;

        public RegistryMetadata() {}
        public RegistryMetadata(String path, String key, String value) {
            this.path = path; this.key = key; this.value = value;
        }

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public String getKey() { return key; }
        public void setKey(String key) { this.key = key; }
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
    }

    public static class BlueOpsMetadata {
        private String schemaVersion;
        private Instant ingestionTimestamp;
        private String collector;
        private String normalizationStatus;

        public BlueOpsMetadata() {}
        public BlueOpsMetadata(String schemaVersion, Instant ingestionTimestamp, String collector, String normalizationStatus) {
            this.schemaVersion = schemaVersion; this.ingestionTimestamp = ingestionTimestamp;
            this.collector = collector; this.normalizationStatus = normalizationStatus;
        }

        public String getSchemaVersion() { return schemaVersion; }
        public void setSchemaVersion(String schemaVersion) { this.schemaVersion = schemaVersion; }
        public Instant getIngestionTimestamp() { return ingestionTimestamp; }
        public void setIngestionTimestamp(Instant ingestionTimestamp) { this.ingestionTimestamp = ingestionTimestamp; }
        public String getCollector() { return collector; }
        public void setCollector(String collector) { this.collector = collector; }
        public String getNormalizationStatus() { return normalizationStatus; }
        public void setNormalizationStatus(String normalizationStatus) { this.normalizationStatus = normalizationStatus; }
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    public EventMetadata getEvent() { return event; }
    public void setEvent(EventMetadata event) { this.event = event; }
    public HostMetadata getHost() { return host; }
    public void setHost(HostMetadata host) { this.host = host; }
    public UserMetadata getUser() { return user; }
    public void setUser(UserMetadata user) { this.user = user; }
    public ProcessMetadata getProcess() { return process; }
    public void setProcess(ProcessMetadata process) { this.process = process; }
    public NetworkEndpoint getSource() { return source; }
    public void setSource(NetworkEndpoint source) { this.source = source; }
    public NetworkEndpoint getDestination() { return destination; }
    public void setDestination(NetworkEndpoint destination) { this.destination = destination; }
    public NetworkMetadata getNetwork() { return network; }
    public void setNetwork(NetworkMetadata network) { this.network = network; }
    public FileMetadata getFile() { return file; }
    public void setFile(FileMetadata file) { this.file = file; }
    public RegistryMetadata getRegistry() { return registry; }
    public void setRegistry(RegistryMetadata registry) { this.registry = registry; }
    public List<String> getRelatedIps() { return relatedIps; }
    public void setRelatedIps(List<String> relatedIps) { this.relatedIps = relatedIps; }
    public List<String> getRelatedUsers() { return relatedUsers; }
    public void setRelatedUsers(List<String> relatedUsers) { this.relatedUsers = relatedUsers; }
    public List<String> getRelatedHashes() { return relatedHashes; }
    public void setRelatedHashes(List<String> relatedHashes) { this.relatedHashes = relatedHashes; }
    public BlueOpsMetadata getBlueops() { return blueops; }
    public void setBlueops(BlueOpsMetadata blueops) { this.blueops = blueops; }
}
