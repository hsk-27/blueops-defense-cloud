package com.blueops.system;

import com.blueops.detections.sigma.SigmaRuleParser;
import com.blueops.detections.sigma.SigmaRuleRegistry;
import com.blueops.findings.OpenSearchFindingAdapter;
import com.blueops.telemetry.EventNormalizationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

public class SystemDiagnosticsAndHealthTest {

    static class HealthyDataSourceStub implements DataSource {
        @Override
        public Connection getConnection() {
            return (Connection) Proxy.newProxyInstance(
                    getClass().getClassLoader(),
                    new Class<?>[]{Connection.class},
                    (proxy, method, args) -> {
                        if ("createStatement".equals(method.getName())) {
                            return (Statement) Proxy.newProxyInstance(
                                    getClass().getClassLoader(),
                                    new Class<?>[]{Statement.class},
                                    (p2, m2, a2) -> {
                                        if ("execute".equals(m2.getName())) return true;
                                        return null;
                                    }
                            );
                        }
                        return null;
                    }
            );
        }

        @Override public Connection getConnection(String u, String p) { return getConnection(); }
        @Override public PrintWriter getLogWriter() { return null; }
        @Override public void setLogWriter(PrintWriter out) {}
        @Override public void setLoginTimeout(int seconds) {}
        @Override public int getLoginTimeout() { return 0; }
        @Override public Logger getParentLogger() throws SQLFeatureNotSupportedException { throw new SQLFeatureNotSupportedException(); }
        @Override public <T> T unwrap(Class<T> iface) { return null; }
        @Override public boolean isWrapperFor(Class<?> iface) { return false; }
    }

    static class FailingDataSourceStub implements DataSource {
        @Override
        public Connection getConnection() throws SQLException {
            throw new SQLException("Connection refused: postgres offline");
        }
        @Override public Connection getConnection(String u, String p) throws SQLException { return getConnection(); }
        @Override public PrintWriter getLogWriter() { return null; }
        @Override public void setLogWriter(PrintWriter out) {}
        @Override public void setLoginTimeout(int seconds) {}
        @Override public int getLoginTimeout() { return 0; }
        @Override public Logger getParentLogger() throws SQLFeatureNotSupportedException { throw new SQLFeatureNotSupportedException(); }
        @Override public <T> T unwrap(Class<T> iface) { return null; }
        @Override public boolean isWrapperFor(Class<?> iface) { return false; }
    }

    @Test
    @DisplayName("HealthIndicator reports UP when database connection is healthy")
    public void testHealthIndicatorUp() {
        DataSource healthyDs = new HealthyDataSourceStub();
        SigmaRuleRegistry registry = new SigmaRuleRegistry(new SigmaRuleParser(), "non_existent_dir");
        EventNormalizationService norm = new EventNormalizationService();

        BlueOpsHealthIndicator indicator = new BlueOpsHealthIndicator(healthyDs, registry, norm);

        Health health = indicator.health();
        assertEquals(Status.UP, health.getStatus());
        assertEquals("CONNECTED", health.getDetails().get("database"));
        assertEquals("OPERATIONAL", health.getDetails().get("platformStatus"));
        assertTrue(health.getDetails().containsKey("sigmaRulesLoaded"));
        assertTrue(health.getDetails().containsKey("telemetryBuffered"));
    }

    @Test
    @DisplayName("HealthIndicator reports DOWN when database connection fails")
    public void testHealthIndicatorDownOnDbFailure() {
        DataSource failingDs = new FailingDataSourceStub();
        SigmaRuleRegistry registry = new SigmaRuleRegistry(new SigmaRuleParser(), "non_existent_dir");
        EventNormalizationService norm = new EventNormalizationService();

        BlueOpsHealthIndicator indicator = new BlueOpsHealthIndicator(failingDs, registry, norm);

        Health health = indicator.health();
        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("DISCONNECTED", health.getDetails().get("database"));
        assertEquals("DEGRADED_DATABASE_DOWN", health.getDetails().get("platformStatus"));
    }

    @Test
    @DisplayName("SystemDiagnosticsController /health returns 200 UP")
    public void testSystemHealthEndpoint() {
        DataSource healthyDs = new HealthyDataSourceStub();
        SigmaRuleRegistry registry = new SigmaRuleRegistry(new SigmaRuleParser(), "non_existent_dir");
        EventNormalizationService norm = new EventNormalizationService();
        OpenSearchFindingAdapter os = new OpenSearchFindingAdapter(new RestTemplateBuilder(), "http://localhost:9200", "admin", "admin", false);

        SystemDiagnosticsController controller = new SystemDiagnosticsController(registry, norm, os, null, healthyDs);

        ResponseEntity<Map<String, Object>> response = controller.getSystemHealth();
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(response.getBody());
        assertEquals("UP", response.getBody().get("status"));
        assertEquals("CONNECTED", response.getBody().get("database"));
    }

    @Test
    @DisplayName("SystemDiagnosticsController /diagnostics provides sanitized operational metrics without leaking secrets")
    public void testSystemDiagnosticsEndpoint() {
        DataSource healthyDs = new HealthyDataSourceStub();
        SigmaRuleRegistry registry = new SigmaRuleRegistry(new SigmaRuleParser(), "non_existent_dir");
        EventNormalizationService norm = new EventNormalizationService();
        OpenSearchFindingAdapter os = new OpenSearchFindingAdapter(new RestTemplateBuilder(), "http://localhost:9200", "admin", "admin", false);

        SystemDiagnosticsController controller = new SystemDiagnosticsController(registry, norm, os, null, healthyDs);

        ResponseEntity<SystemDiagnosticsDto> response = controller.getSystemDiagnostics();
        assertEquals(200, response.getStatusCode().value());
        SystemDiagnosticsDto body = response.getBody();
        assertNotNull(body);
        assertEquals("HEALTHY", body.getStatus());
        assertNotNull(body.getUptimeFormatted());
        assertTrue(body.getMemory().containsKey("maxMemoryMb"));
        assertTrue(body.getMemory().containsKey("usedMemoryMb"));
        assertTrue(body.getTelemetryPipeline().containsKey("bufferedCount"));
        assertTrue(body.getDetectionEngine().containsKey("activeSigmaRules"));
    }
}
