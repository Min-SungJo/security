package com.ride.security.auth;

import com.ride.security.member.Role;
import lombok.*;

@Getter
@ToString
public class RegisterRequest {
    private final String name;
    private final String email;
    private final String password;

    @Builder
    public RegisterRequest(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }
}
