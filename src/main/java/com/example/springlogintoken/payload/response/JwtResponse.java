package com.example.springlogintoken.payload.response;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class JwtResponse {

    private Long id;
    private String username;
    private String email;
    private List<String> roles;

    private String accessToken;

    private String refreshToken;

    private String tokenType = "Bearer";

    public JwtResponse(Long id, String username, String email, List<String> roles, String accessToken) {
        this.accessToken = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public JwtResponse(Long id, String username, String email, List<String> roles, String accessToken, String refreshToken) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
