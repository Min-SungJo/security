package com.ride.security.dto;

import com.ride.security.entity.Role;
import lombok.*;

@Getter
@ToString
public class RegisterRequest {
    private String name;
    private String email;
    private String password;
    private Role role;

    @Builder
    public RegisterRequest(String name, String email, String password, Role role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
    }
}
