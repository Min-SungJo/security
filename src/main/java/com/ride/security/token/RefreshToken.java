package com.ride.security.token;



import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;

import java.io.Serializable;


@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@RedisHash(value = "refreshToken", timeToLive = 7 * 24 * 60 * 60 * 1000) // 7일
public class RefreshToken implements Serializable {

    @Id
    private String token;
    @Indexed
    private Integer memberId;

    @Builder
    public RefreshToken(String token, Integer memberId) {
        this.token = token;
        this.memberId = memberId;
    }
}
