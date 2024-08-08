package com.example.webauthn_demo.auth.controller;

import com.example.webauthn_demo.auth.dto.AuthenticationRequest;
import com.example.webauthn_demo.auth.dto.RegistrationRequest;
import com.example.webauthn_demo.auth.service.AuthService;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final Logger log = LoggerFactory.getLogger(getClass());

    @PostMapping("/register-options")
    public ResponseEntity<Map<String, Object>> getRegisterOptions(@RequestBody String usernameJson, HttpSession session) {
        try {
            log.info("Received register-options request for username: {}", usernameJson);
            PublicKeyCredentialCreationOptions options = authService.startRegistration(usernameJson, session);
            Map<String, Object> response = authService.convertToMap(options);
            log.info("Generated register-options: {}", response);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.info("Error generating register-options for username", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegistrationRequest request, HttpSession session) {
        try {
            log.info("사용자 등록 요청 수신: {}", request.getUsername());
            authService.registerUser(request, session);
            Map<String, String> response = Map.of("status", "성공");
            log.info("사용자 등록 성공: {}", request.getUsername());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("사용자 등록 실패: {}", request.getUsername(), e);
            Map<String, String> errorResponse = Map.of("error", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @GetMapping("/login-options")
    public ResponseEntity<?> getLoginOptions(HttpSession session) {
        try {
            log.info("Received login-options request");
            AssertionRequest assertionRequest = authService.startAuthentication();
            log.info("AssertionRequest options: {}", assertionRequest);

            // AssertionRequest에서 publicKeyCredentialRequestOptions만 추출하여 응답으로 반환
            Map<String, Object> response = new HashMap<>();
            response.put("publicKeyCredentialRequestOptions", assertionRequest.getPublicKeyCredentialRequestOptions());
            log.info("Generated login-options: {}", response);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.info("Error generating login-options", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody AuthenticationRequest request) {
        try {
            log.info("로그인 요청 수신: {}", request.getId());
            boolean success = authService.authenticateUser(request);
            if (success) {
                log.info("사용자 인증 성공: {}", request.getId());
                return ResponseEntity.ok(Map.of("status", "성공"));
            } else {
                log.warn("사용자 인증 실패: {}", request.getId());
                return ResponseEntity.badRequest().body(Map.of("error", "인증 실패"));
            }
        } catch (Exception e) {
            log.error("사용자 인증 실패: {}", request.getId(), e);
            return ResponseEntity.badRequest().body(Map.of("error", "인증 실패: " + e.getMessage()));
        }
    }
}
