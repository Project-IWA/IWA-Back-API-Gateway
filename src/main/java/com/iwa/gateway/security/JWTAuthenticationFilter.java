package com.iwa.gateway.security;

import com.iwa.gateway.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

@Component
public class JWTAuthenticationFilter implements WebFilter {

    @Autowired
    private JWTGenerator tokenGenerator;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // logic for permitAll paths
        PathPatternParser pathPatternParser = new PathPatternParser();
        PathPattern pathPattern = pathPatternParser.parse("/users-api/api/auth/**");
        boolean shouldSkip = pathPattern.matches(exchange.getRequest().getPath().pathWithinApplication());

        if (shouldSkip) {
            return chain.filter(exchange); // Skip further processing for permitAll paths
        }

        // logic for JWT validation
        ServerHttpRequest request = exchange.getRequest();
        String token = getJWTFromRequest(request);

        System.out.println("token: " + token);

        System.out.println("tokenGenerator.validateToken(token): " + tokenGenerator.validateToken(token));
        if (token != null && tokenGenerator.validateToken(token)) {

            System.out.println("token is valid");
            String username = tokenGenerator.getUsernameFromJWT(token);

            System.out.println("username: " + username);
            Mono<User> userDetailsMono = customUserDetailsService.findByUsername(username);

            System.out.println("userDetailsMono: " + userDetailsMono);

            return userDetailsMono.flatMap(userDetails -> {
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                return chain.filter(exchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authenticationToken));
            });
        }

        return chain.filter(exchange);
    }

    private String getJWTFromRequest(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
