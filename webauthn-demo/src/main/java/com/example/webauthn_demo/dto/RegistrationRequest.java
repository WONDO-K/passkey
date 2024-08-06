package com.example.webauthn_demo.dto;

import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import lombok.Data;

@Data
public class RegistrationRequest {
    private String username;
    private String id;
    private String rawId;
    private AuthenticatorAttestationResponseDTO attestation;
    private ClientRegistrationExtensionOutputs clientExtensionResults;

    @Data
    public class AuthenticatorAttestationResponseDTO {
        private String clientDataJSON;
        private String attestationObject;
    }
}

