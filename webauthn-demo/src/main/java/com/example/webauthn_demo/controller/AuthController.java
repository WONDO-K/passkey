package com.example.webauthn_demo.controller;

import com.example.webauthn_demo.dto.AuthenticationRequest;
import com.example.webauthn_demo.dto.RegistrationRequest;
import com.example.webauthn_demo.service.AuthService;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.*;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final Logger log = LoggerFactory.getLogger(getClass());

    @PostMapping("/register-options")
    public ResponseEntity<Map<String, Object>> getRegisterOptions(@RequestBody String username) {
        try {
            log.info("Received register-options request for username: {}", username);
            PublicKeyCredentialCreationOptions options = authService.startRegistration(username);

            // PublicKeyCredentialCreationOptions를 명시적으로 Map으로 변환
            Map<String, Object> response = new HashMap<>();
            response.put("rp", Map.of("name", options.getRp().getName(), "id", options.getRp().getId()));
            response.put("user", Map.of(
                    "name", options.getUser().getName(),
                    "displayName", options.getUser().getDisplayName(),
                    "id", options.getUser().getId().getBase64Url()
            ));
            response.put("challenge", options.getChallenge().getBase64Url());
            response.put("pubKeyCredParams", List.of(
                    Map.of("alg", COSEAlgorithmIdentifier.ES256.getId(), "type", PublicKeyCredentialType.PUBLIC_KEY.getId()),
                    Map.of("alg", COSEAlgorithmIdentifier.RS256.getId(), "type", PublicKeyCredentialType.PUBLIC_KEY.getId())
            ));

            log.info("Generated register-options: {}", response);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Error generating register-options for username", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }


    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegistrationRequest request) {
        try {
            log.info("클라이언트로부터 전달받은 request: {}", request);
            log.info("클라이언트로부터 전달받은 id :{}", request.getId());
            log.info("회원 가입 요청을 받았습니다. 사용자 이름: {}", request.getUsername());

            if (request.getId() == null || request.getId().isEmpty()) {
                throw new IllegalArgumentException("유효하지 않은 ID: ID는 null이거나 빈 값일 수 없습니다.");
            }

            ByteArray id = new ByteArray(Base64.getUrlDecoder().decode(request.getId()));
            ByteArray rawId = new ByteArray(Base64.getUrlDecoder().decode(request.getRawId()));
            ByteArray clientDataJSON = new ByteArray(Base64.getUrlDecoder().decode(request.getAttestation().getClientDataJSON()));
            ByteArray attestationObject = new ByteArray(Base64.getUrlDecoder().decode(request.getAttestation().getAttestationObject()));

            AuthenticatorAttestationResponse attestationResponse = AuthenticatorAttestationResponse.builder()
                    .attestationObject(attestationObject)
                    .clientDataJSON(clientDataJSON)
                    .build();

            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential =
                    PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                            .id(id)
                            .response(attestationResponse)
                            .clientExtensionResults(request.getClientExtensionResults())
                            .type(PublicKeyCredentialType.PUBLIC_KEY)
                            .build();

            log.info("사용자 등록 성공 전 : {}", request.getUsername());
            authService.finishRegistration(request.getUsername(), credential, rawId);
            log.info("사용자 등록 성공: {}", request.getUsername());

            // 클라이언트가 원하는 형식으로 응답을 매핑
            Map<String, Object> response = new HashMap<>();
            response.put("username", request.getUsername());
            response.put("credential", Map.of(
                    "id", request.getId(),
                    "rawId", request.getRawId(),
                    "type", "public-key",
                    "response", Map.of(
                            "attestationObject", request.getAttestation().getAttestationObject(),
                            "clientDataJSON", request.getAttestation().getClientDataJSON()
                    )
            ));

            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            log.error("유효하지 않은 등록 데이터: 사용자 이름: {}", request.getUsername(), e);
            return ResponseEntity.badRequest().body("유효하지 않은 등록 데이터: " + e.getMessage());
        } catch (Exception e) {
            log.error("사용자 등록 실패: 사용자 이름: {}", request.getUsername(), e);
            return ResponseEntity.badRequest().body("등록 실패: " + e.getMessage());
        }
    }

    @GetMapping("/login-options")
    public ResponseEntity<AssertionRequest> getLoginOptions() {
        try {
            log.info("Received login-options request");
            AssertionRequest options = authService.startAuthentication();
            log.info("Generated login-options");
            return ResponseEntity.ok(options);
        } catch (Exception e) {
            log.error("Error generating login-options", e);
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest request) {
        try {
            log.info("Received login request for id: {}", request.getId());
            ByteArray id = new ByteArray(Base64.getUrlDecoder().decode(request.getId()));
            ByteArray clientDataJSON = new ByteArray(Base64.getUrlDecoder().decode(request.getAssertion().getClientDataJSON()));
            ByteArray authenticatorData = new ByteArray(Base64.getUrlDecoder().decode(request.getAssertion().getAuthenticatorData()));
            ByteArray signature = new ByteArray(Base64.getUrlDecoder().decode(request.getAssertion().getSignature()));
            ByteArray userHandle = request.getAssertion().getUserHandle() != null
                    ? new ByteArray(Base64.getUrlDecoder().decode(request.getAssertion().getUserHandle()))
                    : null;

            AuthenticatorAssertionResponse assertionResponse = AuthenticatorAssertionResponse.builder()
                    .authenticatorData(authenticatorData)
                    .clientDataJSON(clientDataJSON)
                    .signature(signature)
                    .userHandle(userHandle)
                    .build();

            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                    PublicKeyCredential.<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>builder()
                            .id(id)
                            .response(assertionResponse)
                            .clientExtensionResults(request.getClientExtensionResults())
                            .type(PublicKeyCredentialType.PUBLIC_KEY)
                            .build();

            boolean success = authService.finishAuthentication(credential);
            if (success) {
                log.info("User authentication successful for id: {}", request.getId());
                return ResponseEntity.ok().build();
            } else {
                log.warn("Authentication failed for id: {}", request.getId());
                return ResponseEntity.badRequest().body("Authentication failed");
            }
        } catch (IllegalArgumentException e) {
            log.error("Invalid authentication data for id: {}", request.getId(), e);
            return ResponseEntity.badRequest().body("Invalid authentication data: " + e.getMessage());
        } catch (Exception e) {
            log.error("Authentication failed for id: {}", request.getId(), e);
            return ResponseEntity.badRequest().body("Authentication failed: " + e.getMessage());
        }
    }
}
