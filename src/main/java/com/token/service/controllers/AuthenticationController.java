package com.token.service.controllers;

import com.token.service.exceptions.TokenServiceException;
import com.token.service.models.LoginRequest;
import com.token.service.models.TokenResponse;
import com.token.service.services.UserService;
import com.token.service.utils.JsonUtils;
import com.token.service.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/authentication")
@Slf4j
public class AuthenticationController {

    private final JwtUtils jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    @Autowired
    public AuthenticationController(JwtUtils jwtUtil, AuthenticationManager authenticationManager, UserService userService) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) throws IOException {
        log.info("Received login request for username: {}", loginRequest.getUsername());
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        log.info("Authentication successful for username: {}", loginRequest.getUsername());
        String token = jwtUtil.generateToken(loginRequest.getUsername());
        TokenResponse tokenResponse = new TokenResponse(token);
        return ResponseEntity.ok(tokenResponse);
    }

    @GetMapping("/validate/{token}")
    public ResponseEntity<Void> validateToken(@PathVariable String token) {
        String username = jwtUtil.extractUsername(token);
        UserDetails userDetails = userService.loadUserByUsername(username);
        
        if (jwtUtil.isTokenExpired(token)) {
            throw new TokenServiceException("Token is expired", "102");
        }
        
        if (!jwtUtil.validateToken(token, userDetails)) {
            throw new TokenServiceException("Invalid Token", "102");
        }

        log.info("Token authentication successful for username: {}", username);
        return ResponseEntity.ok().build();
    }
}
