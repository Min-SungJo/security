package com.ride.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // 비밀 키, JWT 서명에 사용되는 비밀 키입니다.
    @Value("${application.security.jwt.secret-key}")
    private String SECRET_KEY;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;
    /**
     * JWT에서 username을 저장하고 있는
     * 페이로드의 SUB 내용 추출
     *
     * @param token
     * @return username
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * 토큰에서 특정 Claim을 추출
     * 이름, 권한, 만료시간 등을 추출
     *
     * @param token
     * @param claimsResolver - 객체를 받고, 필요한 타입(T)을 반환
     * @param <T>
     * @return claims
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 토큰 생성 1
     * 간단한 토큰 생성을 위해 사용
     *
     * @param userDetails
     * @return token
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * 토큰 생성 2
     * 더 복잡한 구조의 토큰을 만들 수 있게 함
     * 사용자 정의 클레임을 추가할 수 있음
     *
     * @param extraClaims - 추가할 사용자 정의 클레임
     * @param userDetails - 사용자 정보
     * @return token
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts
                .builder()
                .setClaims(extraClaims) // 추가 정보를 담을 객체
                .setSubject(userDetails.getUsername()) // Sub를 username으로 설정
                .setIssuedAt(new Date((System.currentTimeMillis()))) // 토큰 생성 시간
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // 토큰 만료 시간(현재부터 24시간)
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // 서명 알고리즘 및 키 설정
                .compact(); // 생성된 정보를 기반으로 토큰 문자열 생성
    }
    /**
     * 토큰 유효성 검증
     * 토큰의 username이 userDetails와 일치하고, 토큰이 만료되지 않았는지 확인
     *
     * @param token
     * @param member
     * @return isTokenValid - 토큰이 유효한지 여부
     */
    public boolean isTokenValid(String token, UserDetails member) {
        final String username = extractUsername(token);
        return (username.equals(member.getUsername())) && !isTokenExpired(token);
    }

    /**
     * 토큰 만료 여부 확인
     *
     * @param token
     * @return isTokenExpired - 토큰이 만료되었는지 여부
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * 토큰에서 만료 시간 추출
     *
     * @param token
     * @return expirationDate - 토큰의 만료 시간
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * 토큰을 Claims로 파싱(분해)
     * 토큰의 서명을 검증하고, 클레임을 추출
     *
     * @param token
     * @return claims - 토큰의 클레임
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 서명 키 생성 및 반환
     * SECRET_KEY를 기반으로 서명 키 생성
     *
     * @return Key - 서명에 사용될 키
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}