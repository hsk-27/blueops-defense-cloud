package com.blueops.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/v1/auth/login",
                    "/api/v1/auth/refresh",
                    "/api/v1/auth/logout",
                    "/api/v1/system/health",
                    "/actuator/health",
                    "/actuator/info",
                    "/v3/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html"
                ).permitAll()
                // Admin-restricted operations
                .requestMatchers(HttpMethod.POST, "/api/v1/response/actions/*/approve").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/actions/*/reject").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/actions/*/execute").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/actions/*/rollback").hasRole("ADMIN")
                // Controlled SOAR governance endpoints (least-privilege RBAC)
                .requestMatchers(HttpMethod.GET, "/api/v1/response/soar/**").hasAnyRole("ADMIN", "ANALYST", "VIEWER")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/soar/policy-preview").hasAnyRole("ADMIN", "ANALYST")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/soar/proposals").hasAnyRole("ADMIN", "ANALYST")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/soar/proposals/*/cancel").hasAnyRole("ADMIN", "ANALYST")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/soar/proposals/*/approve").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/soar/proposals/*/deny").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/v1/response/soar/proposals/*/execute").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/v1/assets/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/v1/threat-intel/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/v1/detections/**", "/api/v1/detection-rules/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/v1/detections/**", "/api/v1/detection-rules/**").hasRole("ADMIN")
                // General authenticated API endpoints
                .requestMatchers("/api/v1/**").authenticated()
                .anyRequest().permitAll()
            );

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000", "http://127.0.0.1:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept", "X-Requested-With", "Origin"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
