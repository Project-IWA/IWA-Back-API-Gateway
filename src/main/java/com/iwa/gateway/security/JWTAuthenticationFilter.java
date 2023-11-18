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
        PathPattern pathPatternLogin = pathPatternParser.parse("/users-api/api/auth/login");
        PathPattern pathPatternRegister = pathPatternParser.parse("/users-api/api/auth/register");
        boolean shouldSkipLogin = pathPatternLogin.matches(exchange.getRequest().getPath().pathWithinApplication());
        boolean shouldSkipRegister = pathPatternRegister.matches(exchange.getRequest().getPath().pathWithinApplication());

        if (shouldSkipLogin || shouldSkipRegister){
            return chain.filter(exchange); // Skip further processing for permitAll paths
        }

        // logic for JWT validation - get the token from the request
        ServerHttpRequest request = exchange.getRequest();
        String token = getJWTFromRequest(request);

        // Validate the token
        boolean isTokenValid = tokenGenerator.validateToken(token);
        if (token != null && isTokenValid) {
            // extract the user details from the token
            String username = tokenGenerator.getUsernameFromJWT(token);
            Long userId = tokenGenerator.getUserIdFromToken(token);
            String role = tokenGenerator.getRoleFromToken(token);

            // Add attributes to the request
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("AuthUserId", userId.toString())
                    .header("AuthUsername", username)
                    .header("AuthUserRole", role)
                    .build();

            // Mutate the exchange with the new request containing the headers
            ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

            // Get the user details from the database and set the authentication in the context
            Mono<User> userDetailsMono = customUserDetailsService.findByUsername(username);
            return userDetailsMono.flatMap(userDetails -> {
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                return chain.filter(mutatedExchange)
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
