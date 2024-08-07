package com.example.webauthn_demo.auth.dto;

import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import lombok.Data;

@Data
public class RegistrationRequest {
    private String username;
    private Credential credential;
    private ClientRegistrationExtensionOutputs clientExtensionResults; // 빈 객체로 넘어올 필드 (선택사항이라서)

    @Data
    public static class Credential {
        private String id;
        private byte[] rawId; // byte[]로 수정
        private String type;
        private AuthenticatorAttestationResponseDTO response;
    }

    @Data
    public static class AuthenticatorAttestationResponseDTO {
        private byte[] clientDataJSON; // 문자열 대신 byte[]로 변경
        private byte[] attestationObject; // 문자열 대신 byte[]로 변경
    }
}
