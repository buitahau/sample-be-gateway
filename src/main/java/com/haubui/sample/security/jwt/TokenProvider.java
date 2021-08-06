package com.haubui.sample.security.jwt;

import com.haubui.sample.constant.GatewayConstant;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider {

    private String _BASE64_SECRET;

    private long _tokenValidityInMilliseconds;

    private long _tokenValidityInMillisecondsForRememberMe;

    private final JwtParser _jwtParser;

    private final Key _key;

    private static final String _AUTHORITIES_KEY = "auth";

    private static final String _DELIMITER_COMMA = ",";

    private static final Logger _log = LoggerFactory.getLogger(TokenProvider.class);

    public TokenProvider(
        @Value("${app.security.authentication.base64-secret}") String BASE64_SECRET,
        @Value("${app.security.authentication.token-validity-in-seconds}") long tokenValidityInMilliseconds,
        @Value("${app.security.authentication.token-validity-in-seconds-for-remember-me}") long tokenValidityInMillisecondsForRememberMe) {

        this._BASE64_SECRET = BASE64_SECRET;
        byte[] keyBytes = Decoders.BASE64.decode(_BASE64_SECRET);
        _key = Keys.hmacShaKeyFor(keyBytes);
        _jwtParser = Jwts.parserBuilder().setSigningKey(_key).build();
        _tokenValidityInMilliseconds = 1000 * tokenValidityInMilliseconds;
        _tokenValidityInMillisecondsForRememberMe = 1000 * tokenValidityInMillisecondsForRememberMe;
    }

    public String createToken(Authentication authentication, boolean rememberMe) {
        String authorities = authentication
            .getAuthorities()
            .stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(_DELIMITER_COMMA));

        long now = new Date().getTime();
        Date validity;
        if (rememberMe) {
            validity = new Date(now + _tokenValidityInMillisecondsForRememberMe);
        } else {
            validity = new Date(now + _tokenValidityInMilliseconds);
        }

        return Jwts
            .builder()
            .setSubject(authentication.getName())
            .claim(_AUTHORITIES_KEY, authorities)
            .signWith(_key, SignatureAlgorithm.HS512)
            .setExpiration(validity)
            .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = _jwtParser.parseClaimsJws(token).getBody();

        Collection<? extends GrantedAuthority> authorities = Arrays
            .stream(claims.get(_AUTHORITIES_KEY).toString().split(_DELIMITER_COMMA))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), GatewayConstant.BLANK, authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean validateToken(String token, HttpServletRequest httpServletRequest) {
        try {
            _jwtParser.parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException expiredJwtException) {
            _log.error("Expired JWT token.");
            httpServletRequest.setAttribute("expired", expiredJwtException.getMessage());
        } catch (JwtException | IllegalArgumentException e) {
            _log.error("Invalid JWT token.");
            _log.trace("Invalid JWT token trace.", e);
        }
        return false;
    }
}
