package vn.sugu.hb3_java.configuration;

import vn.sugu.hb3_java.entity.User;
import vn.sugu.hb3_java.enums.UserRole;
import vn.sugu.hb3_java.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;

@Configuration
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class ApplicationInitConfig {

    PasswordEncoder passwordEncoder;

    @Bean
    ApplicationRunner applicationRunner(UserRepository userRepository) {
        return args -> {
            if (userRepository.findByName("admin").isEmpty()) {
                User user = User.builder()
                        .name("admin")
                        .accountCode("admin001")
                        .password(passwordEncoder.encode("admin"))
                        .role(UserRole.ADMIN)
                        .build();

                userRepository.save(user);
                log.warn("Admin user has been created with default password: 'admin'. Please change it immediately.");
            }
        };
    }
}
