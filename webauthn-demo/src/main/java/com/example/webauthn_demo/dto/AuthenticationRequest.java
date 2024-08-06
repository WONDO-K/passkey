package com.example.webauthn_demo.dto;


import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import lombok.Data;

@Data
public class AuthenticationRequest {
    private String id;
    private String rawId;
    private AuthenticatorAssertionResponseDTO assertion;
    private ClientAssertionExtensionOutputs clientExtensionResults;

    @Data
    public class AuthenticatorAssertionResponseDTO {
        private String clientDataJSON;
        private String authenticatorData;
        private String signature;
        private String userHandle;
    }
}


