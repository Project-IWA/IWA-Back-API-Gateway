package com.iwa.gateway.security;

import java.util.Date;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class JWTGenerator {

    private String key  = SecurityConstants.JWT_SECRET;

    public String getUsernameFromJWT(String token){
        Claims claims = Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            System.out.println("token before parser : " + token);
            Jwts.parser()
                    .setSigningKey(key)
                    .parseClaimsJws(token);
            return true;
        } catch (Exception ex) {
            // Log the exception details here, if necessary
            System.out.println("Token validation error: " + ex.getMessage());
            return false;
        }
    }

}
