package com.ride.security.token;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RedisRefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken findByToken(String refreshToken) {
        return refreshTokenRepository.findById(refreshToken).orElse(null);
    }

    public void deleteRefreshToken(String token) {
        refreshTokenRepository.deleteById(token);
    }

    public boolean isRefreshTokenPresent(String refreshToken) {
        return refreshTokenRepository.findById(refreshToken).isPresent();
    }
}
