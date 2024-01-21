package com.ride.security.config;

import com.ride.security.repository.TokenRepository;
import com.ride.security.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter { // 요청당 한 번씩 실행되는 필터

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request, // 들어오는 요청
            @NonNull HttpServletResponse response, // 나가는 응답
            @NonNull FilterChain filterChain // 필터 체인
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization"); // 'Authorization' 헤더 값 가져오기
        final String jwt; // JWT 토큰을 저장할 변수
        final String userEmail; // 사용자 이메일을 저장할 변수
        if (authHeader == null || !authHeader.startsWith("Bearer ")) { // 헤더 검증
            filterChain.doFilter(request, response); // 다음 필터로 요청 전달
            return;
        }
        jwt = authHeader.substring(7); // "Bearer " 제거 후 JWT 추출
        userEmail = jwtService.extractUsername(jwt); // JWT에서 사용자 이메일 추출
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) { // 사용자 이메일과 현재 인증이 없는 경우
            UserDetails member = this.userDetailsService.loadUserByUsername(userEmail); // 사용자 상세 정보 가져오기
            var isTokenValid = tokenRepository.findByToken(jwt)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);
            if (isTokenValid && jwtService.isTokenValid(jwt, member)) { // JWT 유효성 검증
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        member, // 사용자 상세
                        null, // 자격 증명
                        member.getAuthorities() // 권한
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request) // 요청의 세부 정보 설정
                );
                SecurityContextHolder.getContext().setAuthentication(authToken); // 인증 정보를 보안 컨텍스트에 설정
            }
        }
        filterChain.doFilter(request, response); // 다음 필터로 요청 전달
    }
}