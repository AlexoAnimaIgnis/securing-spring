package com.alexo.demo.springsecuringapp.security.jwt;

import com.alexo.demo.springsecuringapp.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.secure.app.jwtSecret}")
    private String jwtSecret;
    @Value("${spring.secure.app.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationInMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try{
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
        } catch(MalformedJwtException e) {
            logger.error("Invalid JWT token", e);
        } catch(ExpiredJwtException e) {
            logger.error("Expired JWT token", e);
        } catch(UnsupportedJwtException e) {
            logger.error("Unsupported JWT token", e);
        } catch(IllegalArgumentException e) {
            logger.error("JWT claims string is empty", e);
        }
        return false;
    }
}
