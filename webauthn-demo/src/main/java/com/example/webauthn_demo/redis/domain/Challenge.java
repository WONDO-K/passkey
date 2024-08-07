package com.example.webauthn_demo.redis.domain;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Data
@RedisHash("Challenge") // Redis에 저장할 해시 네임을 지정
public class Challenge {

    @Id
    private String username; // 사용자 이름을 키로 사용
    private byte[] challenge; // 챌린지 데이터
}