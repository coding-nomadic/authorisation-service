package com.token.service.models;

import lombok.Data;

@Data
public class RegistrationRequest {
    private String fullName;
    private String userName;
    private String email;
    private String password;
    private String mobileNumber;
}