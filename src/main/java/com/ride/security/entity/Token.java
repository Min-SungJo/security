package com.ride.security.entity;

import jakarta.persistence.*;
import lombok.*;

@Getter
@ToString
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class Token {

    @Id @GeneratedValue
    private Integer id;
    private String token;
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;
    @Setter
    private boolean expired;
    @Setter
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "member_id")
    private Member member;

    @Builder
    public Token(Integer id, String token, TokenType tokenType, boolean expired, boolean revoked, Member member) {
        this.id = id;
        this.token = token;
        this.tokenType = tokenType;
        this.expired = expired;
        this.revoked = revoked;
        this.member = member;
    }
}
