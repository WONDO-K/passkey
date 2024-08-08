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
            log.info("사용자 등록 옵션 요청 수신: {}", usernameJson);
            PublicKeyCredentialCreationOptions options = authService.startRegistration(usernameJson, session);
            Map<String, Object> response = authService.convertToMap(options);
            log.info("생성된 사용자 등록 옵션: {}", response);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.info("사용자 등록 옵션 생성 중 오류 발생: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegistrationRequest request, HttpSession session) {
        try {
            log.info("사용자 등록 요청 수신: {}", request.getUsername());
            authService.registerUser(request, session);
            log.info("사용자 등록 성공: {}", request.getUsername());
            return ResponseEntity.ok(Map.of("status", "성공"));
        } catch (Exception e) {
            log.info("사용자 등록 실패: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/login-options")
    public ResponseEntity<Map<String, Object>> getLoginOptions(HttpSession session) {
        try {
            log.info("로그인 옵션 요청 수신");
            AssertionRequest assertionRequest = authService.startAuthentication();
            Map<String, Object> response = new HashMap<>();
            response.put("publicKeyCredentialRequestOptions", assertionRequest.getPublicKeyCredentialRequestOptions());
            log.info("생성된 로그인 옵션: {}", response);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.info("로그인 옵션 생성 중 오류 발생: {}", e.getMessage());
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
                log.info("사용자 인증 실패: {}", request.getId());
                return ResponseEntity.badRequest().body(Map.of("error", "인증 실패"));
            }
        } catch (Exception e) {
            log.info("사용자 인증 중 오류 발생: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", "인증 실패: " + e.getMessage()));
        }
    }
}
