package com.token.service.controllers;

import com.token.service.services.EmailService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/email")
@Slf4j
public class EmailSenderController {

    @Autowired
    private EmailService emailService;

    @GetMapping
    public void sendMail(@RequestParam String emailTo, @RequestParam String emailText) {
        emailService.sendMail(emailTo, emailText);
        log.info("sent email to senders successfully !");
    }
}
