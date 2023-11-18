package com.iwa.gateway.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class JWTGenerator {

    @Value("${jwt.secret}")
    private String key;

    public String getUsernameFromJWT(String token){
        Claims claims = Jwts.parser()
                .setSigningKey(key.getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public String getRoleFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(key.getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();

        return claims.get("role", String.class);
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(key.getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();

        return claims.get("userId", Long.class);
    }


    public boolean validateToken(String token) {
        try {
            System.out.println("token before parser : " + token);
            System.out.println("key : " + key);
            Jwts.parser()
                    .setSigningKey(key.getBytes(StandardCharsets.UTF_8))
                    .parseClaimsJws(token);
            return true;
        } catch (AuthenticationCredentialsNotFoundException ex) {
            // Log the exception details here, if necessary
            System.out.println("Token not found: " + ex.getMessage());
            return false;
        } catch (ExpiredJwtException ex) {
            // Log the exception details here, if necessary
            System.out.println("Token expired: " + ex.getMessage());
            return false;
        } catch(UnsupportedJwtException ex){
            System.out.println("Unsupported JWT: " + ex.getMessage());
            return false;
        } catch(IllegalArgumentException ex){
            System.out.println("JWT claims string is empty: " + ex.getMessage());
            return false;
        } catch (SignatureException ex) {
            // Log the exception details here, if necessary
            System.out.println("Token signature error: " + ex.getMessage());
            return false;
        } catch (MalformedJwtException ex) {
            // Log the exception details here, if necessary
            System.out.println("Token malformed: " + ex.getMessage());
            return false;
        } catch (Exception ex) {
            // Log the exception details here, if necessary
            System.out.println("Token validation error: " + ex.getMessage());
            return false;
        }
    }

}
