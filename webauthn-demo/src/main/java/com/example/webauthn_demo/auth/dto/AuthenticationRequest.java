package com.example.webauthn_demo.auth.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.Base64;

@Data
@NoArgsConstructor
public class AuthenticationRequest {

    private String id;
    private String rawId;
    private AuthenticatorAssertionResponseDTO assertion;
    private ClientAssertionExtensionOutputs clientExtensionResults;
    private String challenge;
    private String username;  // username 필드 추가

    @JsonCreator
    public AuthenticationRequest(
            @JsonProperty("id") String id,
            @JsonProperty("rawId") String rawId,
            @JsonProperty("assertion") AuthenticatorAssertionResponseDTO assertion,
            @JsonProperty("clientExtensionResults") ClientAssertionExtensionOutputs clientExtensionResults,
            @JsonProperty("challenge") String challenge,
            @JsonProperty("username") String username) { // username 필드 추가
        this.id = id;
        this.rawId = rawId;
        this.assertion = assertion;
        this.clientExtensionResults = clientExtensionResults;
        this.challenge = challenge;
        this.username = username;
    }

    public byte[] getChallengeBytes() {
        return Base64.getUrlDecoder().decode(this.challenge);
    }

    @Data
    @NoArgsConstructor
    public static class AuthenticatorAssertionResponseDTO {
        private String clientDataJSON;
        private String authenticatorData;
        private String signature;

        @JsonCreator
        public AuthenticatorAssertionResponseDTO(
                @JsonProperty("clientDataJSON") String clientDataJSON,
                @JsonProperty("authenticatorData") String authenticatorData,
                @JsonProperty("signature") String signature) {
            this.clientDataJSON = clientDataJSON;
            this.authenticatorData = authenticatorData;
            this.signature = signature;
        }
    }
}
