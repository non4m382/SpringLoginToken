package com.example.springlogintoken.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;


public class AuthTokenFilter extends OncePerRequestFilter {

    @Value("${bezkoder.app.jwtSecret}")
    private String secret;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = parseJwt(request);

        Optional<Authentication> authentication = this.createAuthentication(token);

        authentication.ifPresent(authentication2 -> SecurityContextHolder.getContext().setAuthentication(authentication2));

        filterChain.doFilter(request, response);

    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }

    public Optional<Authentication> createAuthentication(String token) {
        
        Jws<Claims> jwsClaims = validateToken(token);


        Claims claims = jwsClaims.getBody();
        String rolesString = claims.get("scopes").toString();

        String[] authStrings = rolesString.replaceAll("[\\[\\]]", "").trim().split(",");


        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(authStrings)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        String subject = claims.getSubject();
        org.springframework.security.core.userdetails.User principal = new User(subject, "", authorities);

        return Optional.of(new UsernamePasswordAuthenticationToken(principal, token, authorities));
    }

    private Jws<Claims> validateToken(String authToken) {
        try {
            return Jwts.parser().setSigningKey(secret).parseClaimsJws(authToken);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }
}
