package com.ride.security.config;

import com.ride.security.token.AccessTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final AccessTokenRepository accessTokenRepository;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization"); // 'Authorization' 헤더 값 가져오기
        final String jwt; // JWT 토큰을 저장할 변수
        if (authHeader == null || !authHeader.startsWith("Bearer ")) { // 헤더 검증
            return;
        }
        jwt = authHeader.substring(7); // "Bearer " 제거 후 JWT 추출
        var storedToken = accessTokenRepository.findByToken(jwt)
                .orElse(null);
        if (storedToken != null) {
            storedToken.setExpired(true);
            storedToken.setRevoked(true);
            accessTokenRepository.save(storedToken);
        }
    }
}
