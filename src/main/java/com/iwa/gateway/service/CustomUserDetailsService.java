package com.iwa.gateway.service;

import com.iwa.gateway.dto.UserDetailsDTO;
import com.iwa.gateway.model.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

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
        // Make a call to the Users microservice to fetch user details
        return webClientBuilder.build()
                .get()
                .uri(usersServiceUrl + "/{username}", username)
                .retrieve()
                .bodyToMono(UserDetailsDTO.class) // Assuming UserData is the concrete class you use
                .map(userDetailsDTO -> {
                    // Create a Spring Security User object from the retrieved data
                    return new User(userDetailsDTO.getUsername(), userDetailsDTO.getPassword(), mapRolesToAuthorities(userDetailsDTO.getRoles()));
                })
                .doOnError(error -> {
                    // Handle errors, for example, logging or returning a default user details
                });
    }

    private Collection<GrantedAuthority> mapRolesToAuthorities(List<Role> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());
    }

}

