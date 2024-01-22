package com.ride.security.auth;

import lombok.*;

@Getter
@ToString
public class AuthenticationRequest {
    private final String email;
    private final String password;

    @Builder
    public AuthenticationRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }
}
