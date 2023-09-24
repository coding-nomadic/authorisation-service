package com.token.service.services;

import com.token.service.entities.Role;
import com.token.service.entities.User;
import com.token.service.exceptions.TokenServiceException;
import com.token.service.models.RegistrationRequest;
import com.token.service.repository.RoleRepository;
import com.token.service.repository.UserRepository;
import com.token.service.utils.EmailUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional
@Slf4j
public class RegistrationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Value("${api.url}")
    private String apiUrl;

    private static final String USERNAME_EXISTS_ERROR_CODE = "104";
    private static final String EMAIL_EXISTS_ERROR_CODE = "105";
    private static final String TOKEN_NOT_FOUND_ERROR_CODE = "102";

    public RegistrationService(UserRepository userRepository, RoleRepository roleRepository,
                              PasswordEncoder passwordEncoder, EmailService emailService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    public void registerUser(RegistrationRequest registrationRequest) {
        if (userRepository.existsByUserName(registrationRequest.getUserName())) {
            throw new TokenServiceException("Username already exists!", USERNAME_EXISTS_ERROR_CODE);
        }
        if (userRepository.existsByEmail(registrationRequest.getEmail())) {
            throw new TokenServiceException("Email already exists!", EMAIL_EXISTS_ERROR_CODE);
        }
        String tokenForNewUser = UUID.randomUUID().toString();
        User user = createUserFromRegistrationRequest(registrationRequest, tokenForNewUser);
        userRepository.save(user);
        String link = apiUrl + "/signup/confirm?token=" + tokenForNewUser;
        emailService.sendMail(registrationRequest.getEmail(), EmailUtils.buildEmail(registrationRequest.getFullName(), link));
    }

    private User createUserFromRegistrationRequest(RegistrationRequest registrationRequest, String token) {
        User user = new User();
        user.setUserName(registrationRequest.getUserName());
        user.setFullName(registrationRequest.getFullName());
        user.setEmail(registrationRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        user.setMobileNumber(registrationRequest.getMobileNumber());
        user.setToken(token);
        user.setEnabled(false);
        return user;
    }

    public String confirmToken(String token) {
        if (userRepository.existsByToken(token)) {
            log.info("Token exists in the user DB, hence updating the isEnabled parameter");
        } else {
            throw new TokenServiceException("Token not found for the user", TOKEN_NOT_FOUND_ERROR_CODE);
        }
        Optional<User> userOptional = userRepository.findByToken(token);
        User user = userOptional.orElseThrow(() -> new TokenServiceException("Not found", TOKEN_NOT_FOUND_ERROR_CODE));
        user.setEnabled(true);
        userRepository.save(user);
        log.info("isEnabled Parameter is updated in DB");
        return "Your email is confirmed. Thank you for using our service!";
    }
}
