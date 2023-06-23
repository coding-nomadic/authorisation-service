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
@Slf4j
public class AuthenticationController {

    @Autowired
    private JwtUtils jwtUtil;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService service;

    @PostMapping(path = "/authenticate")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) throws IOException {
        log.info("Request Body for Login {}", JsonUtils.toString(loginRequest));
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        log.info("Authentication Successful !");
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setToken(jwtUtil.generateToken(loginRequest.getUsername()));
        return new ResponseEntity<>(tokenResponse, HttpStatus.OK);
    }

    @GetMapping(path = "/authenticate/{token}")
    public ResponseEntity<Void> login(@PathVariable String token) throws IOException {
        System.out.println("--->"+token);
        String userName = jwtUtil.extractUsername(token);
        UserDetails userDetails = service.loadUserByUsername(userName);
        if(jwtUtil.isTokenExpired(token)){
            throw new TokenServiceException("Token is expired","102");
        }
        if(!jwtUtil.validateToken(token, userDetails)){
            throw new TokenServiceException("Invalid Token","102");
        }
        log.info("Token Authentication Successful !");
        return new ResponseEntity<>(HttpStatus.OK);
    }
}