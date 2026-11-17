package com.blueops.detections.sigma;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Registry and dynamic loader for Sigma detection rules.
 * Automatically scans rule directories, indexes rules by code and technique,
 * and enables runtime rule reloads without backend restarts.
 */
@Component
public class SigmaRuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(SigmaRuleRegistry.class);

    private final SigmaRuleParser parser;
    private final String customSigmaPath;
    private final Map<String, SigmaRuleDefinition> rulesByCode = new ConcurrentHashMap<>();
    private final Map<String, SigmaRuleDefinition> rulesById = new ConcurrentHashMap<>();

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

    public synchronized int reloadRules() {
        rulesByCode.clear();
        rulesById.clear();

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

        try (Stream<Path> paths = Files.walk(activeRoot)) {
            paths.filter(Files::isRegularFile)
                 .filter(p -> p.toString().endsWith(".yml") || p.toString().endsWith(".yaml"))
                 .forEach(this::loadRuleFile);
        } catch (IOException e) {
            log.error("Failed to traverse Sigma rule directory: {}", e.getMessage(), e);
        }

        log.info("Successfully loaded and registered {} Sigma detection rules dynamically.", rulesByCode.size());
        return rulesByCode.size();
    }

    private void loadRuleFile(Path file) {
        try (FileInputStream fis = new FileInputStream(file.toFile())) {
            String filename = file.getFileName().toString();
            SigmaRuleDefinition rule = parser.parse(fis, filename);
            if (rule != null) {
                if (rule.getRuleCode() != null) {
                    rulesByCode.put(rule.getRuleCode().toUpperCase(), rule);
                }
                if (rule.getId() != null) {
                    rulesById.put(rule.getId(), rule);
                }
                log.debug("Loaded Sigma rule: [{}] {} (Severity: {})", rule.getRuleCode(), rule.getTitle(), rule.getLevel());
            }
        } catch (Exception ex) {
            log.error("Failed to parse Sigma rule file {}: {}", file.getFileName(), ex.getMessage());
        }
    }

    public Optional<SigmaRuleDefinition> getRuleByCode(String code) {
        if (code == null) return Optional.empty();
        return Optional.ofNullable(rulesByCode.get(code.toUpperCase()));
    }

    public Optional<SigmaRuleDefinition> getRuleById(String id) {
        if (id == null) return Optional.empty();
        return Optional.ofNullable(rulesById.get(id));
    }

    public List<SigmaRuleDefinition> getAllRules() {
        return new ArrayList<>(rulesByCode.values());
    }

    public int getLoadedRuleCount() {
        return rulesByCode.size();
    }

    public List<SigmaRuleDefinition> getRulesByLogSourceProduct(String product) {
        if (product == null) return Collections.emptyList();
        return rulesByCode.values().stream()
                .filter(r -> r.getLogsource() != null && product.equalsIgnoreCase(String.valueOf(r.getLogsource().get("product"))))
                .toList();
    }

    private List<Path> getCandidateSigmaRoots() {
        List<Path> candidates = new ArrayList<>();
        if (customSigmaPath != null && !customSigmaPath.isBlank()) {
            candidates.add(Paths.get(customSigmaPath));
        }
        // Standard relative paths from workspace and backend
        candidates.add(Paths.get("detection-rules", "sigma"));
        candidates.add(Paths.get("..", "detection-rules", "sigma"));
        candidates.add(Paths.get(".", "detection-rules", "sigma"));
        candidates.add(Paths.get("C:", "Users", "Dell", ".gemini", "antigravity", "scratch", "blueops-defense-cloud", "detection-rules", "sigma"));
        return candidates;
    }
}
