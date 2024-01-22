package com.ride.security.service;

import com.ride.security.entity.RefreshToken;
import com.ride.security.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RedisRefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken findByToken(String token) {
        return refreshTokenRepository.findById(token).orElse(null);
    }

    public boolean isRefreshTokenPresent(String refreshToken, UserDetails member) {
        final String email = member.getUsername();
        Optional<RefreshToken> redisToken = refreshTokenRepository.findByEmailAndToken(email, refreshToken);
        return redisToken.isPresent();
    }

    public void deleteRefreshToken(String token) {
        refreshTokenRepository.deleteById(token);
    }
}
