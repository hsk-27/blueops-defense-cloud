package com.blueops.security;

import com.blueops.users.Role;
import com.blueops.users.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;
    private final String testSecret = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider(testSecret, 3600000, 86400000);
    }

    @Test
    void testGenerateAndValidateAccessToken() {
        User user = new User("soc_analyst", "analyst@blueops.internal", "hashed", "SOC Analyst", Role.ROLE_ANALYST);
        user.setId(10L);
        CustomUserDetails userDetails = new CustomUserDetails(user);
        Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        String token = jwtTokenProvider.generateAccessToken(auth);
        assertNotNull(token);
        assertTrue(jwtTokenProvider.validateToken(token));
        assertEquals("soc_analyst", jwtTokenProvider.getUsernameFromJwt(token));
    }

    @Test
    void testInvalidTokenReturnsFalse() {
        assertFalse(jwtTokenProvider.validateToken("invalid.jwt.token"));
    }
}
