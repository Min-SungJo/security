package com.ride.security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ride.security.dto.AuthenticationRequest;
import com.ride.security.dto.AuthenticationResponse;
import com.ride.security.dto.RegisterRequest;
import com.ride.security.entity.Member;
import com.ride.security.entity.Role;
import com.ride.security.entity.Token;
import com.ride.security.entity.TokenType;
import com.ride.security.repository.MemberRepository;
import com.ride.security.repository.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    /**
     * 사용자 등록 및 토큰(JWT) 발급
     *
     * @param request - 사용자 정보
     * @return AuthenticationResponse 사용자 정보로 만든 토큰(JWT)
     */
    public AuthenticationResponse register(RegisterRequest request) {
        var member = Member.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // 비밀번호 암호화
                .role(request.getRole())
                .build();
        var savedMember = memberRepository.save(member); // 회원 정보 저장
        var jwtToken = jwtService.generateToken(member); // access 토큰 생성
        var refreshToken = jwtService.generateRefreshToken(savedMember); // refresh 토큰 생성
        saveMemberToken(savedMember, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build(); // 생성된 토큰으로 AuthenticationResponse 반환
    }

    /**
     * 사용자 인증 및 토큰(JWT) 발급
     *
     * @param request - 사용자 인증 데이터
     * @return 사용자 인증 정보로 만든 토큰(JWT)
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate( // 사용자 인증
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var member = memberRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Member not found")); // 사용자 조회
        var jwtToken = jwtService.generateToken(member); // JWT 토큰 생성
        var refreshToken = jwtService.generateRefreshToken(member);
        revokeAllMemberTokens(member);
        saveMemberToken(member, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build(); // 생성된 토큰으로 AuthenticationResponse 반환
    }

    private void revokeAllMemberTokens(Member member) {
        var validMemberToken = tokenRepository.findAllValidTokensByMember(member.getId());
        if (validMemberToken.isEmpty()) return;
        validMemberToken.forEach(t -> {
            t.setRevoked(true);
            t.setExpired(true);
        });
        tokenRepository.saveAll(validMemberToken);
    }

    /**
     * DB에 토큰(JWT) 저장
     *
     * @param member   - DB 에 있는 사용자 자료형(TABLE)
     * @param jwtToken - 생성된(저장할) 토큰
     */
    private void saveMemberToken(Member member, String jwtToken) {
        var token = Token.builder()
                .member(member)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(AUTHORIZATION);
        final String refreshToken;
        final String memberEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        memberEmail = jwtService.extractUsername(refreshToken);
        if (memberEmail != null) {
            var member = memberRepository.findByEmail(memberEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Member not found"));
//            var isTokenValid = tokenRepository.findByToken(refreshToken) // refreshToken 을 저장할 경우, 만료, 취소 로직을 작성하는 위치
//                    .map(t -> !t.isExpired() && !t.isRevoked())
//                    .orElse(false);
//                storedToken.setExpired(true);
//                storedToken.setRevoked(true);
//                tokenRepository.save(storedToken);

            if (jwtService.isTokenValid(refreshToken, member)) { // JWT 유효성 검증
                var accessToken = jwtService.generateToken(member);
                revokeAllMemberTokens(member);
                saveMemberToken(member, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}