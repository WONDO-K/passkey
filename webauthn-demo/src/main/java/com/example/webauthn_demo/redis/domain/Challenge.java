package com.example.webauthn_demo.redis.domain;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Data
@RedisHash(value = "Challenge", timeToLive = 90) // 90초
public class Challenge {

    @Id
    private String username;
    private byte[] challenge;
}
