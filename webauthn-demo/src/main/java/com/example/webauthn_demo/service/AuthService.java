package com.example.webauthn_demo.service;

import com.example.webauthn_demo.model.Passkey;
import com.example.webauthn_demo.model.User;
import com.example.webauthn_demo.repository.PasskeyRepository;
import com.example.webauthn_demo.repository.UserRepository;
import com.example.webauthn_demo.repository.WebAuthnCredentialRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${rp.id}")
    private String rpId;

    @Value("${rp.name}")
    private String rpName;

    @Value("${rp.origin}")
    private String rpOrigin;

    private final UserRepository userRepository;
    private final PasskeyRepository passkeyRepository;
    private final WebAuthnCredentialRepository webAuthnCredentialRepository;
    private RelyingParty relyingParty;
    private final SecureRandom random = new SecureRandom();
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final HttpSession httpSession;

    @PostConstruct
    public void init() {
        this.relyingParty = RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder()
                        .id(rpId)
                        .name(rpName)
                        .build())
                .credentialRepository(webAuthnCredentialRepository)
                .origins(Set.of(rpOrigin))
                .build();
    }

    public PublicKeyCredentialCreationOptions startRegistration(String usernameJson) {
        try {
            // JSON 파싱
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode usernameNode = objectMapper.readTree(usernameJson);
            String username = usernameNode.get("username").asText();

            // User 객체 검색 또는 생성
            User user = userRepository.findByUsername(username)
                    .orElseGet(() -> {
                        User newUser = new User();
                        newUser.setUsername(username);
                        newUser.setDisplayName(username);
                        return userRepository.save(newUser);
                    });

            log.info("Username retrieved: {}", user.getUsername());
            log.info("DisplayName retrieved: {}", user.getDisplayName());

            ByteArray userId = new ByteArray(user.getId().toString().getBytes());

            UserIdentity userIdentity = UserIdentity.builder()
                    .name(user.getUsername())
                    .displayName(user.getDisplayName())
                    .id(userId)
                    .build();

            ByteArray challenge = generateChallenge();

            // 챌린지를 세션에 저장합니다.
            httpSession.setAttribute("challenge", challenge);

            PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.builder()
                    .rp(relyingParty.getIdentity())
                    .user(userIdentity)
                    .challenge(challenge)
                    .pubKeyCredParams(List.of(
                            PublicKeyCredentialParameters.builder()
                                    .alg(COSEAlgorithmIdentifier.ES256)
                                    .type(PublicKeyCredentialType.PUBLIC_KEY)
                                    .build()
                    ))
                    .build();

            log.info("Generated PublicKeyCredentialCreationOptions: {}", options);

            return options;

        } catch (Exception e) {
            log.error("Error parsing username JSON", e);
            throw new IllegalArgumentException("Invalid username JSON", e);
        }
    }

    public void finishRegistration(String username, PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential, ByteArray rawId)
            throws RegistrationFailedException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // 세션에서 챌린지를 불러옵니다.
        ByteArray savedChallenge = (ByteArray) httpSession.getAttribute("challenge");
        if (savedChallenge == null) {
            log.error("No challenge found in session for user: {}", username);
            throw new IllegalStateException("No challenge found in session");
        }

        FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                .request(PublicKeyCredentialCreationOptions.builder()
                        .rp(relyingParty.getIdentity())
                        .user(UserIdentity.builder()
                                .name(user.getUsername())
                                .displayName(user.getDisplayName())
                                .id(new ByteArray(user.getId().toString().getBytes()))
                                .build())
                        .challenge(savedChallenge) // 저장된 챌린지를 사용
                        .pubKeyCredParams(List.of(PublicKeyCredentialParameters.ES256))
                        .build())
                .response(credential)
                .build();

        RegistrationResult result = relyingParty.finishRegistration(options);

        Passkey passkey = new Passkey();
        passkey.setCredentialId(result.getKeyId().getId().getBase64());
        passkey.setRawId(rawId.getBase64()); // rawId를 저장
        passkey.setPublicKey(result.getPublicKeyCose().getBytes());
        passkey.setUser(user);
        passkeyRepository.save(passkey);

        log.info("Saved Passkey with rawId: {}", rawId.getBase64());
    }

    public AssertionRequest startAuthentication() {
        return relyingParty.startAssertion(StartAssertionOptions.builder().build());
    }

    public boolean finishAuthentication(PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential) {
        Optional<Passkey> passkeyOpt = passkeyRepository.findById(credential.getId().getBase64());

        if (passkeyOpt.isEmpty()) {
            return false;
        }

        Passkey passkey = passkeyOpt.get();
        User user = passkey.getUser();

        try {
            AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(relyingParty.startAssertion(StartAssertionOptions.builder().build()))
                    .response(credential)
                    .build());

            log.info("Assertion result for user {}: {}", user.getUsername(), result.isSuccess());
            return result.isSuccess();
        } catch (AssertionFailedException e) {
            log.error("Assertion failed", e);
            return false;
        }
    }

    private ByteArray generateChallenge() {
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        return new ByteArray(challenge);
    }
}
