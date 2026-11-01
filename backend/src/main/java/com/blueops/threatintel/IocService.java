package com.blueops.threatintel;

import com.blueops.common.exceptions.InvalidActionException;
import com.blueops.common.exceptions.ResourceNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.BufferedReader;
import java.io.StringReader;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class IocService {

    private final IocIndicatorRepository iocRepository;
    private final IocMatchRepository matchRepository;

    public IocService(IocIndicatorRepository iocRepository, IocMatchRepository matchRepository) {
        this.iocRepository = iocRepository;
        this.matchRepository = matchRepository;
    }

    @Transactional(readOnly = true)
    public List<IocDto> getAllIocs() {
        return iocRepository.findAll().stream()
                .map(IocDto::new)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public IocDto getIocById(Long id) {
        IocIndicator ioc = iocRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("IOC", "id", id));
        return new IocDto(ioc);
    }

    @Transactional
    public IocDto createIoc(IocDto dto) {
        validateIndicator(dto.getIndicatorValue(), dto.getIndicatorType());

        if (iocRepository.existsByIndicatorValueAndIndicatorType(dto.getIndicatorValue(), dto.getIndicatorType())) {
            throw new InvalidActionException("Indicator already registered: " + dto.getIndicatorValue());
        }

        IocIndicator ioc = new IocIndicator();
        ioc.setIndicatorValue(dto.getIndicatorValue().trim());
        ioc.setIndicatorType(dto.getIndicatorType());
        ioc.setSource(dto.getSource());
        ioc.setConfidence(dto.getConfidence());
        ioc.setSeverity(dto.getSeverity() != null ? dto.getSeverity() : "HIGH");
        ioc.setDescription(dto.getDescription());
        ioc.setStatus(dto.getStatus() != null ? dto.getStatus() : "ACTIVE");
        ioc.setTags(dto.getTags());
        ioc.setFirstSeenAt(Instant.now());
        ioc.setLastSeenAt(Instant.now());
        ioc.setExpiresAt(dto.getExpiresAt());

        return new IocDto(iocRepository.save(ioc));
    }

    @Transactional
    public IocDto updateIoc(Long id, IocDto dto) {
        IocIndicator ioc = iocRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("IOC", "id", id));

        ioc.setConfidence(dto.getConfidence());
        ioc.setSeverity(dto.getSeverity());
        ioc.setDescription(dto.getDescription());
        ioc.setStatus(dto.getStatus());
        ioc.setTags(dto.getTags());
        ioc.setExpiresAt(dto.getExpiresAt());
        ioc.setLastSeenAt(Instant.now());

        return new IocDto(iocRepository.save(ioc));
    }

    @Transactional
    public void deleteIoc(Long id) {
        if (!iocRepository.existsById(id)) {
            throw new ResourceNotFoundException("IOC", "id", id);
        }
        iocRepository.deleteById(id);
    }

    @Transactional
    public Map<String, Object> importIocsFromCsv(String csvContent) {
        int imported = 0;
        int skipped = 0;
        List<String> errors = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new StringReader(csvContent))) {
            String line;
            boolean firstLine = true;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (firstLine && line.toLowerCase().contains("indicator_value")) {
                    firstLine = false;
                    continue;
                }
                firstLine = false;

                String[] tokens = line.split(",");
                if (tokens.length < 3) {
                    errors.add("Invalid line format: " + line);
                    skipped++;
                    continue;
                }

                String val = tokens[0].trim();
                String typeStr = tokens[1].trim().toUpperCase();
                String src = tokens[2].trim();
                int conf = tokens.length > 3 ? Integer.parseInt(tokens[3].trim()) : 80;
                String sev = tokens.length > 4 ? tokens[4].trim() : "HIGH";

                try {
                    IocType type = IocType.valueOf(typeStr);
                    if (!iocRepository.existsByIndicatorValueAndIndicatorType(val, type)) {
                        IocIndicator ioc = new IocIndicator();
                        ioc.setIndicatorValue(val);
                        ioc.setIndicatorType(type);
                        ioc.setSource(src);
                        ioc.setConfidence(conf);
                        ioc.setSeverity(sev);
                        ioc.setStatus("ACTIVE");
                        ioc.setFirstSeenAt(Instant.now());
                        ioc.setLastSeenAt(Instant.now());
                        iocRepository.save(ioc);
                        imported++;
                    } else {
                        skipped++;
                    }
                } catch (Exception ex) {
                    errors.add("Failed to import " + val + ": " + ex.getMessage());
                    skipped++;
                }
            }
        } catch (Exception ex) {
            throw new InvalidActionException("Failed to read CSV: " + ex.getMessage());
        }

        Map<String, Object> result = new HashMap<>();
        result.put("imported", imported);
        result.put("skipped", skipped);
        result.put("errors", errors);
        return result;
    }

    @Transactional(readOnly = true)
    public List<IocMatch> getRecentMatches() {
        return matchRepository.findTop50ByOrderByEventTimestampDesc();
    }

    @Transactional(readOnly = true)
    public List<String> getSources() {
        return iocRepository.findAll().stream()
                .map(IocIndicator::getSource)
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    private void validateIndicator(String value, IocType type) {
        if (value == null || value.isBlank()) {
            throw new InvalidActionException("Indicator value cannot be empty");
        }
        if (type == IocType.SHA256 && value.trim().length() != 64) {
            throw new InvalidActionException("SHA256 indicator must be exactly 64 hexadecimal characters");
        }
        if (type == IocType.MD5 && value.trim().length() != 32) {
            throw new InvalidActionException("MD5 indicator must be exactly 32 hexadecimal characters");
        }
    }
}
