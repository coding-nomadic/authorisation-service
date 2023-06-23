package com.token.service.controllers;

;
import com.token.service.models.RegistrationRequest;
import com.token.service.services.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/signup")
public class RegistrationController {

    @Autowired
    RegistrationService registrationService;

    @PostMapping
    public ResponseEntity<Void> signUp(@RequestBody RegistrationRequest registrationRequest) {
        registrationService.registerUser(registrationRequest);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @GetMapping(path = "/confirm")
    public String confirm(@RequestParam("token") String token) {
        return registrationService.confirmToken(token);
    }
}