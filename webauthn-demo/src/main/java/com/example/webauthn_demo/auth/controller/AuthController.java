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
            log.error("Error generating register-options for username", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegistrationRequest request, HttpSession session) {
        try {
            log.info("Received registration request for username: {}", request.getUsername());
            authService.registerUser(request, session);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("Registration failed for username: {}", request.getUsername(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/login-options")
    public ResponseEntity<AssertionRequest> getLoginOptions(HttpSession session) {
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
            boolean success = authService.authenticateUser(request);
            if (success) {
                log.info("User authentication successful for id: {}", request.getId());
                return ResponseEntity.ok().build();
            } else {
                log.warn("Authentication failed for id: {}", request.getId());
                return ResponseEntity.badRequest().body("Authentication failed");
            }
        } catch (Exception e) {
            log.error("Authentication failed for id: {}", request.getId(), e);
            return ResponseEntity.badRequest().body("Authentication failed: " + e.getMessage());
        }
    }
}
