package com.example.springlogintoken.advice;

import com.example.springlogintoken.exception.TokenRefreshException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.Date;

@RestControllerAdvice
public class TokenControllerAdvice {
    @ExceptionHandler(value = TokenRefreshException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public ErrorMessage handleTokenRefreshException(TokenRefreshException ex, WebRequest request) {
        return new ErrorMessage(
                HttpStatus.BAD_GATEWAY.value(),
                new Date(),
                ex.getMessage(),
                request.getDescription(false));
    }
}
