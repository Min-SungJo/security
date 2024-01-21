package com.ride.security.dto;

import lombok.*;

@Getter
@ToString
public class AuthenticationRequest {
    private String email;
    private String password;

    @Builder
    public AuthenticationRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }
}
