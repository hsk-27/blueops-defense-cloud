package com.blueops.auth;

import com.blueops.common.exceptions.UnauthorizedException;
import com.blueops.security.CustomUserDetails;
import com.blueops.security.JwtTokenProvider;
import com.blueops.users.User;
import com.blueops.users.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final JdbcTemplate jdbcTemplate;
    private final LoginRateLimiter rateLimiter;
    private final long jwtExpirationMs;

    public AuthService(
            AuthenticationManager authenticationManager,
            JwtTokenProvider tokenProvider,
            UserRepository userRepository,
            JdbcTemplate jdbcTemplate,
            LoginRateLimiter rateLimiter,
            @Value("${blueops.jwt.expiration-ms:3600000}") long jwtExpirationMs) {
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
        this.userRepository = userRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.rateLimiter = rateLimiter;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    @Transactional
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        String clientIp = httpRequest != null ? httpRequest.getRemoteAddr() : "127.0.0.1";
        String userAgent = httpRequest != null ? httpRequest.getHeader("User-Agent") : "unknown";

        if (rateLimiter.isBlocked(request.getUsername()) || rateLimiter.isBlocked(clientIp)) {
            recordLoginAttempt(request.getUsername(), clientIp, userAgent, "LOCKED_OUT");
            throw new UnauthorizedException("Account is temporarily locked due to repeated failed login attempts. Please try again after 15 minutes.");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            User user = userDetails.getUser();

            rateLimiter.recordSuccess(user.getUsername());
            rateLimiter.recordSuccess(clientIp);

            String accessToken = tokenProvider.generateAccessToken(authentication);
            String refreshToken = tokenProvider.generateRefreshToken(user.getUsername());

            recordLoginAttempt(user.getUsername(), clientIp, userAgent, "SUCCESS");

            return new LoginResponse(
                    accessToken,
                    refreshToken,
                    jwtExpirationMs,
                    user.getUsername(),
                    user.getEmail(),
                    user.getRole().name(),
                    user.getFullName()
            );
        } catch (AuthenticationException ex) {
            rateLimiter.recordFailure(request.getUsername());
            rateLimiter.recordFailure(clientIp);
            recordLoginAttempt(request.getUsername(), clientIp, userAgent, "FAILED_CREDENTIALS");
            throw new UnauthorizedException("Invalid username or password");
        }
    }

    public LoginResponse refresh(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        if (!tokenProvider.validateToken(refreshToken)) {
            throw new UnauthorizedException("Invalid or expired refresh token");
        }

        String username = tokenProvider.getUsernameFromJwt(refreshToken);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UnauthorizedException("User not found"));

        if (!user.isEnabled()) {
            throw new UnauthorizedException("User account is disabled");
        }

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                new CustomUserDetails(user), null, new CustomUserDetails(user).getAuthorities()
        );

        String newAccessToken = tokenProvider.generateAccessToken(authentication);
        String newRefreshToken = tokenProvider.generateRefreshToken(username);

        return new LoginResponse(
                newAccessToken,
                newRefreshToken,
                jwtExpirationMs,
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                user.getFullName()
        );
    }

    public UserDto getCurrentUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UnauthorizedException("User session expired"));
        return new UserDto(user);
    }

    private void recordLoginAttempt(String username, String ip, String userAgent, String status) {
        try {
            jdbcTemplate.update(
                    "INSERT INTO login_history (username, source_ip, user_agent, status, attempted_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    username, ip, userAgent != null && userAgent.length() > 250 ? userAgent.substring(0, 250) : userAgent, status
            );
        } catch (Exception ignored) {
            // Best-effort logging
        }
    }
}
