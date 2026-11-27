package com.blueops.detections.sigma;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

/**
 * Registry and dynamic loader for Sigma detection rules (SEC-003).
 * Automatically scans rule directories, indexes rules by code and technique,
 * and enables lock-free, zero-downtime runtime rule reloads without race windows.
 */
@Component
public class SigmaRuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(SigmaRuleRegistry.class);

    private final SigmaRuleParser parser;
    private final String customSigmaPath;

    // Atomic references holding immutable snapshots of active rules
    private final AtomicReference<Map<String, SigmaRuleDefinition>> rulesByCodeRef = new AtomicReference<>(Collections.emptyMap());
    private final AtomicReference<Map<String, SigmaRuleDefinition>> rulesByIdRef = new AtomicReference<>(Collections.emptyMap());

    public SigmaRuleRegistry(
            SigmaRuleParser parser,
            @Value("${blueops.detections.sigma-path:}") String customSigmaPath) {
        this.parser = parser;
        this.customSigmaPath = customSigmaPath;
    }

    @PostConstruct
    public void initialize() {
        reloadRules();
    }

    /**
     * Atomically reloads Sigma rules from disk.
     * Rules are parsed into temporary staging structures; existing active rules remain fully
     * available to concurrent queries until atomic reference swap at completion.
     */
    public synchronized int reloadRules() {
        List<Path> candidateRoots = getCandidateSigmaRoots();
        Path activeRoot = null;

        for (Path root : candidateRoots) {
            if (Files.exists(root) && Files.isDirectory(root)) {
                activeRoot = root;
                break;
            }
        }

        if (activeRoot == null) {
            log.warn("Sigma rule directory not found in candidate paths. Dynamic Sigma parsing running with 0 external rules.");
            return 0;
        }

        log.info("Loading dynamic Sigma detection rules from directory: {}", activeRoot.toAbsolutePath());

        // Staging maps for atomic swap
        Map<String, SigmaRuleDefinition> stagingByCode = new ConcurrentHashMap<>();
        Map<String, SigmaRuleDefinition> stagingById = new ConcurrentHashMap<>();

        try (Stream<Path> paths = Files.walk(activeRoot)) {
            paths.filter(Files::isRegularFile)
                 .filter(p -> p.toString().endsWith(".yml") || p.toString().endsWith(".yaml"))
                 .forEach(p -> loadRuleFile(p, stagingByCode, stagingById));
        } catch (IOException e) {
            log.error("Failed to traverse Sigma rule directory: {}", e.getMessage(), e);
        }

        // Lock-free atomic reference swap: readers never observe an empty or half-loaded map
        rulesByCodeRef.set(Collections.unmodifiableMap(stagingByCode));
        rulesByIdRef.set(Collections.unmodifiableMap(stagingById));

        log.info("Successfully loaded and registered {} Sigma detection rules dynamically (atomic swap complete).", stagingByCode.size());
        return stagingByCode.size();
    }

    private void loadRuleFile(Path file, Map<String, SigmaRuleDefinition> stagingByCode, Map<String, SigmaRuleDefinition> stagingById) {
        try (FileInputStream fis = new FileInputStream(file.toFile())) {
            String filename = file.getFileName().toString();
            SigmaRuleDefinition rule = parser.parse(fis, filename);
            if (rule != null) {
                if (rule.getRuleCode() != null) {
                    String codeKey = rule.getRuleCode().toUpperCase(Locale.ROOT);
                    SigmaRuleDefinition existing = stagingByCode.putIfAbsent(codeKey, rule);
                    if (existing != null) {
                        log.warn("Duplicate Sigma ruleCode detected during reload: [{}] in file '{}'. Retaining initial definition '{}'.",
                                codeKey, filename, existing.getTitle());
                    }
                }
                if (rule.getId() != null) {
                    SigmaRuleDefinition existingId = stagingById.putIfAbsent(rule.getId(), rule);
                    if (existingId != null) {
                        log.warn("Duplicate Sigma rule ID detected during reload: [{}] in file '{}'.",
                                rule.getId(), filename);
                    }
                }
                log.debug("Loaded Sigma rule: [{}] {} (Severity: {})", rule.getRuleCode(), rule.getTitle(), rule.getLevel());
            }
        } catch (Exception ex) {
            log.error("Failed to parse Sigma rule file {}: {}", file.getFileName(), ex.getMessage());
        }
    }

    public Optional<SigmaRuleDefinition> getRuleByCode(String code) {
        if (code == null) return Optional.empty();
        return Optional.ofNullable(rulesByCodeRef.get().get(code.toUpperCase(Locale.ROOT)));
    }

    public Optional<SigmaRuleDefinition> getRuleById(String id) {
        if (id == null) return Optional.empty();
        return Optional.ofNullable(rulesByIdRef.get().get(id));
    }

    public List<SigmaRuleDefinition> getAllRules() {
        return new ArrayList<>(rulesByCodeRef.get().values());
    }

    public int getLoadedRuleCount() {
        return rulesByCodeRef.get().size();
    }

    public List<SigmaRuleDefinition> getRulesByLogSourceProduct(String product) {
        if (product == null) return Collections.emptyList();
        return rulesByCodeRef.get().values().stream()
                .filter(r -> r.getLogsource() != null && product.equalsIgnoreCase(String.valueOf(r.getLogsource().get("product"))))
                .toList();
    }

    private List<Path> getCandidateSigmaRoots() {
        List<Path> candidates = new ArrayList<>();
        if (customSigmaPath != null && !customSigmaPath.isBlank()) {
            candidates.add(Paths.get(customSigmaPath));
        }
        // Standard portable relative and container paths (no developer machine absolute paths)
        candidates.add(Paths.get("detection-rules", "sigma"));
        candidates.add(Paths.get("..", "detection-rules", "sigma"));
        candidates.add(Paths.get("..", "..", "detection-rules", "sigma"));
        candidates.add(Paths.get(".", "detection-rules", "sigma"));
        candidates.add(Paths.get("/app", "detection-rules", "sigma"));
        return candidates;
    }
}
