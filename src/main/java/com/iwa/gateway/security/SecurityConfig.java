package com.iwa.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JWTAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthEntryPoint jwtAuthEntryPoint;

    // Using constructor injection to autowire the JWTAuthenticationFilter and JwtAuthEntryPoint
    @Autowired
    public SecurityConfig(JWTAuthenticationFilter jwtAuthenticationFilter, JwtAuthEntryPoint jwtAuthEntryPoint) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtAuthEntryPoint = jwtAuthEntryPoint;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) -> Mono.defer(() -> jwtAuthEntryPoint.commence(swe, e)))
                .and()
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/users-api/api/auth/**").permitAll()
                        .anyExchange().authenticated())
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .httpBasic().disable(); // Disabled basic authentication

        return http.build();
    }
}
