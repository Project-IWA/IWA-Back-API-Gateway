package com.iwa.gateway.dto;

import com.iwa.gateway.model.Role;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserDetailsDTO{
    private String username;
    private String password;
    private List<Role> roles;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public List<Role> getRoles() {
        return roles;
    }
}

