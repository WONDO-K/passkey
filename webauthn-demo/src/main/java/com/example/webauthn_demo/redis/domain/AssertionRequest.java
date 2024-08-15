package com.example.webauthn_demo.redis.domain;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Data
@RedisHash("AssertionRequest") // Redis에 저장할 해시 네임을 지정
public class AssertionRequest {

    @Id
    private String credentialId; // credential ID를 키로 사용
    private byte[] requestData; // 요청 데이터 (예: Challenge, 기타 정보)
}
