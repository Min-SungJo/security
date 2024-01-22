package com.ride.security.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Getter
@ToString
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthenticationResponse {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("refresh_token")
    private String refreshToken;

    @Builder
    public AuthenticationResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
