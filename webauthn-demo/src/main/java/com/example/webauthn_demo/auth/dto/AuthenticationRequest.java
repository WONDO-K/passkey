package com.example.webauthn_demo.auth.dto;

import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import lombok.Data;

@Data
public class AuthenticationRequest {
    private String id; // 인증 자격 증명의 ID
    private String rawId; // 인증 자격 증명의 원시 ID
    private AuthenticatorAssertionResponseDTO assertion; // 인증 응답
    private ClientAssertionExtensionOutputs clientExtensionResults; // 클라이언트 확장 결과

    @Data
    public static class AuthenticatorAssertionResponseDTO {
        private String clientDataJSON; // 클라이언트 데이터 JSON
        private String authenticatorData; // 인증 장치 데이터
        private String signature; // 인증 서명
        private String userHandle; // 사용자 핸들 (선택적)
    }
}
