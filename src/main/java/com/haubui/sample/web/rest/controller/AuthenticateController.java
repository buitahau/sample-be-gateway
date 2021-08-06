package com.haubui.sample.web.rest.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.haubui.sample.constant.AuthoritiesConstant;
import com.haubui.sample.security.jwt.TokenProvider;
import com.haubui.sample.web.rest.dto.LoginDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthenticateController {

    @Autowired
    private AuthenticationManagerBuilder _authenticationManagerBuilder;

    @Autowired
    private TokenProvider _tokenProvider;

    @PostMapping("/authenticate")
    public ResponseEntity<JWTToken> authenticate(@Valid @RequestBody LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        Authentication authentication = _authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        String jwt = _tokenProvider.createToken(authentication, loginDto.isRememberMe());
        authentication = _tokenProvider.getAuthentication(jwt);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(AuthoritiesConstant.AUTHORIZATION_HEADER, AuthoritiesConstant.PREFIX_BEARER + jwt);
        return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
    }

    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }

    static class JWTToken {
        private String idToken;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

        @JsonProperty("id_token")
        public String getIdToken() {
            return idToken;
        }

        public void setIdToken(String idToken) {
            this.idToken = idToken;
        }
    }
}
