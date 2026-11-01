package com.blueops.common.init;

import com.blueops.users.Role;
import com.blueops.users.User;
import com.blueops.users.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        seedUserIfNotExists("admin", "admin@blueops.internal", "Admin@BlueOps2026!", "SOC Administrator", Role.ROLE_ADMIN);
        seedUserIfNotExists("analyst", "analyst@blueops.internal", "Analyst@BlueOps2026!", "Tier 2 SOC Analyst", Role.ROLE_ANALYST);
        seedUserIfNotExists("viewer", "viewer@blueops.internal", "Viewer@BlueOps2026!", "Auditor / Readonly Viewer", Role.ROLE_VIEWER);
    }

    private void seedUserIfNotExists(String username, String email, String rawPassword, String fullName, Role role) {
        if (!userRepository.existsByUsername(username)) {
            User user = new User(
                    username,
                    email,
                    passwordEncoder.encode(rawPassword),
                    fullName,
                    role
            );
            userRepository.save(user);
            log.info("Initialized default system user: {} with role {}", username, role);
        }
    }
}
