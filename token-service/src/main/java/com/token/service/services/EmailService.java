package com.token.service.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Service
@Slf4j
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    private static final String SENDER = "tnzngdw@gmail.com";
    private static final String UTF = "utf-8";

    @Async
    public void sendMail(String emailTo, String emailText) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, UTF);
            helper.setText(emailText, true);
            helper.setTo(emailTo);
            helper.setSubject("Confirm your email");
            helper.setFrom(SENDER);
            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            log.error("Failed to send email for: " + emailTo + "\n" + e.getLocalizedMessage());
            throw new IllegalArgumentException("Failed to send email for: " + emailTo);
        }
    }
}