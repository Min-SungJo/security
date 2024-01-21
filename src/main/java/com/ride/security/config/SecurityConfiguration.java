package com.ride.security.config;

import com.ride.security.entity.Permission;
import com.ride.security.entity.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.ride.security.entity.Permission.*;
import static com.ride.security.entity.Role.*;

@Configuration
@EnableWebSecurity // Spring Security 활성화
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    // 주입된 커스텀 JWT 인증 필터
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // 사용자 정의 AuthenticationProvider
    private final AuthenticationProvider authenticationProvider;

    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // CSRF 보호 비활성화
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/**").permitAll() // "/api/v1/auth/**" 경로는 인증 없이 허용
                        .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                        .requestMatchers(HttpMethod.GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                        .requestMatchers(HttpMethod.POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                        .requestMatchers(HttpMethod.PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

//                        .requestMatchers("/api/v1/admin/**").hasAnyRole(ADMIN.name())
//                        .requestMatchers(HttpMethod.GET, "/api/v1/admin/**").hasAnyAuthority(ADMIN_READ.name())
//                        .requestMatchers(HttpMethod.POST, "/api/v1/admin/**").hasAnyAuthority(ADMIN_CREATE.name())
//                        .requestMatchers(HttpMethod.PUT, "/api/v1/admin/**").hasAnyAuthority(ADMIN_UPDATE.name())
//                        .requestMatchers(HttpMethod.DELETE, "/api/v1/admin/**").hasAnyAuthority(ADMIN_DELETE.name())

                        .anyRequest().authenticated()) // 그 외 모든 요청은 인증 필요
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션을 사용하지 않고, Stateless하게 설정
                .authenticationProvider(authenticationProvider) // 커스텀 AuthenticationProvider 설정
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // UsernamePasswordAuthenticationFilter 이전에 jwtAuthenticationFilter 추가
                .logout(logout -> logout
                        .logoutUrl("/api/v1/auth/logout") // Controller 엔드포인트 대신 사용
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler(
                                (request, response, authentication) ->
                                        SecurityContextHolder.clearContext()
                        )
                );
        return http.build();
    }
}
