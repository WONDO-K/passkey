package com.example.webauthn_demo.auth.dto;

import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import lombok.Data;

@Data
public class RegistrationRequest {
    private String username;
    private Credential credential;
    private ClientRegistrationExtensionOutputs clientExtensionResults;

    @Data
    public static class Credential {
        private String id; // Base64로 인코딩된 문자열
        private String rawId; // Base64로 인코딩된 문자열
        private String type;
        private AuthenticatorAttestationResponseDTO response;
    }

    @Data
    public static class AuthenticatorAttestationResponseDTO {
        private String clientDataJSON; // Base64로 인코딩된 문자열
        private String attestationObject; // Base64로 인코딩된 문자열
    }
}
