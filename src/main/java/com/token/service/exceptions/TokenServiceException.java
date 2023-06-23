package com.token.service.exceptions;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)

public class TokenServiceException extends RuntimeException {


    public TokenServiceException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenServiceException(String message, String errorCode) {
        super(message);
    }
}