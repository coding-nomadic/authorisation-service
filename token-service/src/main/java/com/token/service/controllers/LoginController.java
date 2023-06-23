package com.token.service.controllers;


import com.token.service.models.LoginRequest;
import com.token.service.services.LoginService;
import com.token.service.services.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(path = "/api")
public class LoginController {

    @Autowired
    RegistrationService registrationService;

    @Autowired
    private LoginService loginService;

    @GetMapping(path="/logout")
    public ResponseEntity<String> logout() {
        return ResponseEntity.ok("Logged out successfully");
    }
    @PostMapping(path="/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        if (loginService.isLoginSuccessful(loginRequest)) {
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }
}