package com.blueops.response;

import com.blueops.assets.Asset;
import com.blueops.common.exceptions.InvalidActionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ResponsePolicyValidatorTest {

    private final ResponsePolicyValidator validator = new ResponsePolicyValidator();

    @Test
    @DisplayName("Should accept valid target IP and hostname under simulation mode")
    void testValidTargetPasses() {
        ResponsePlaybook playbook = new ResponsePlaybook();
        playbook.setPlaybookCode("P001");
        playbook.setActionType("BLOCK_IP");

        assertDoesNotThrow(() -> validator.validateRequest(playbook, "198.51.100.44", null, true));
        assertDoesNotThrow(() -> validator.validateRequest(playbook, "WIN-SRV-2022", null, true));
    }

    @Test
    @DisplayName("Should reject target with leading hyphen (CLI option injection prevention)")
    void testLeadingHyphenRejected() {
        ResponsePlaybook playbook = new ResponsePlaybook();
        playbook.setPlaybookCode("P002");
        playbook.setActionType("DISABLE_USER");

        assertThrows(InvalidActionException.class, () ->
                validator.validateRequest(playbook, "--help", null, true));
    }

    @Test
    @DisplayName("Should reject target with shell metacharacters")
    void testShellMetacharactersRejected() {
        ResponsePlaybook playbook = new ResponsePlaybook();
        playbook.setPlaybookCode("P001");
        playbook.setActionType("BLOCK_IP");

        assertThrows(InvalidActionException.class, () ->
                validator.validateRequest(playbook, "198.51.100.44; rm -rf /", null, true));
    }

    @Test
    @DisplayName("Should reject actions targeting protected infrastructure (127.0.0.1, localhost)")
    void testProtectedInfrastructureRejected() {
        ResponsePlaybook playbook = new ResponsePlaybook();
        playbook.setPlaybookCode("P003");
        playbook.setActionType("ISOLATE_HOST");

        assertThrows(InvalidActionException.class, () ->
                validator.validateRequest(playbook, "127.0.0.1", null, true));
        assertThrows(InvalidActionException.class, () ->
                validator.validateRequest(playbook, "localhost", null, true));
    }
}
