package com.iwa.gateway.service;

import com.iwa.gateway.dto.UserDetailsDTO;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Collections;

@Service
public class CustomUserDetailsService {

    private final WebClient.Builder webClientBuilder;
    private final String usersServiceUrl; // URL of the Users microservice

    @Autowired
    public CustomUserDetailsService(WebClient.Builder webClientBuilder, @Value("${users.service.url}") String usersServiceUrl) {
        this.webClientBuilder = webClientBuilder;
        this.usersServiceUrl = usersServiceUrl;
    }


    public Mono<User> findByUsername(String username) {
        return webClientBuilder.build()
                .get()
                .uri(usersServiceUrl + "/{username}", username)
                .retrieve()
                .bodyToMono(UserDetailsDTO.class)
                .map(userDetailsDTO -> new User(
                        userDetailsDTO.getUsername(),
                        userDetailsDTO.getPassword(),
                        mapRoleToAuthorities(userDetailsDTO.getRole())
                ))
                .onErrorResume(e -> {
                    System.out.println("Error occurred while retrieving user details: " + e.getMessage());
                    if(e instanceof WebClientResponseException.NotFound)
                        return Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found", e));
                    else if(e instanceof WebClientResponseException.BadRequest)
                        return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "Bad request", e));
                    else
                        return Mono.error(new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error", e));
                });
    }

    /**
     * @param role : the role string to be mapped to authorities
     * **/
    private Collection<GrantedAuthority> mapRoleToAuthorities(String role) {
        GrantedAuthority authority = new SimpleGrantedAuthority(role);
        return Collections.singletonList(authority);
    }

}

