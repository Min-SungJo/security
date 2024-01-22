package com.ride.security.auth;

import com.ride.security.member.Role;
import lombok.*;

@Getter
@ToString
public class RegisterRequest {
    private final String name;
    private final String email;
    private final String password;
    private final Role role;

    @Builder
    public RegisterRequest(String name, String email, String password, Role role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
    }
}
