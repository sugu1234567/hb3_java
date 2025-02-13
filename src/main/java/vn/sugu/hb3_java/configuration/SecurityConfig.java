package vn.sugu.hb3_java.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final String[] PUBLIC_ENDPOINTS = {
            "api/v1/auth/login", "api/v1/auth/introspect", "api/v1/auth/logout", "api/v1/auth/refresh-token",
            "api/v1/password/forgot_password", "api/v1/password/validate-reset-token",
            "api/v1/password/reset-password",
            "/v3/api-docs/**", "/swagger-ui/**",
            "/swagger-ui.html"
    };

    @Autowired
    private CustomJwtDecoder customJwtDecoder;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(request -> request.requestMatchers(HttpMethod.POST, PUBLIC_ENDPOINTS).permitAll()

                        .requestMatchers("/api/v1/users/**").hasAnyRole("ADMIN", "MENTOR", "USER")
                        .requestMatchers("/api/v1/mentor/**").hasAnyRole("ADMIN", "MENTOR")
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")

                        // .requestMatchers(HttpMethod.GET, "/api/v1/users/**").hasAnyRole("ADMIN",
                        // "MENTOR")
                        // .requestMatchers(HttpMethod.GET, "/api/v1/users/**").hasRole("USER")
                        .anyRequest().authenticated());

        httpSecurity.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(customJwtDecoder)
                .jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint()));

        httpSecurity.csrf(AbstractHttpConfigurer::disable);

        return httpSecurity.build();

    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }
}
