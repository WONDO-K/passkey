package com.example.webauthn_demo.auth.service;

import com.example.webauthn_demo.auth.dto.AuthenticationRequest;
import com.example.webauthn_demo.auth.dto.RegistrationRequest;
import com.example.webauthn_demo.auth.model.Passkey;
import com.example.webauthn_demo.auth.model.User;
import com.example.webauthn_demo.auth.repository.PasskeyRepository;
import com.example.webauthn_demo.auth.repository.UserRepository;
import com.example.webauthn_demo.auth.repository.WebAuthnCredentialRepository;
import com.example.webauthn_demo.auth.util.Base64Util;
import com.example.webauthn_demo.redis.service.ChallengeService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;

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
    private final ChallengeService challengeService; // Redis를 통한 챌린지 관리 서비스
    private RelyingParty relyingParty;
    private final SecureRandom random = new SecureRandom();
    private final Logger log = LoggerFactory.getLogger(getClass());

    // 애플리케이션 초기화 시 RelyingParty 객체를 설정
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
        log.info("RelyingParty 초기화 완료: rpId={}, rpName={}, rpOrigin={}", rpId, rpName, rpOrigin);
    }

    // 챌린지를 생성하고 Redis에 저장하는 메서드 (startRegistration)
    public PublicKeyCredentialCreationOptions startRegistration(String usernameJson, HttpSession session) {
        try {
            String username = parseUsername(usernameJson); // 사용자 이름을 JSON에서 파싱
            User user = getUser(username); // 사용자 정보를 조회 또는 새로 생성
            ByteArray userId = new ByteArray(user.getId().toString().getBytes()); // 사용자 ID를 ByteArray로 변환
            ByteArray challenge = generateChallenge(); // 랜덤한 챌린지 생성

            // Redis에 챌린지를 저장 (username을 키로 사용)
            challengeService.saveChallenge(username, challenge.getBytes());
            log.info("Redis에 챌린지가 저장되었습니다. username={}, challenge={}", username, challenge);

            // PublicKeyCredentialCreationOptions 객체를 생성하여 반환
            return PublicKeyCredentialCreationOptions.builder()
                    .rp(relyingParty.getIdentity())
                    .user(UserIdentity.builder()
                            .name(user.getUsername())
                            .displayName(user.getDisplayName())
                            .id(userId)
                            .build())
                    .challenge(challenge)
                    .pubKeyCredParams(List.of(
                            PublicKeyCredentialParameters.builder()
                                    .alg(COSEAlgorithmIdentifier.ES256)
                                    .type(PublicKeyCredentialType.PUBLIC_KEY)
                                    .build(),
                            PublicKeyCredentialParameters.builder()
                                    .alg(COSEAlgorithmIdentifier.RS256)
                                    .type(PublicKeyCredentialType.PUBLIC_KEY)
                                    .build()
                    ))
                    .build();
        } catch (IOException e) {
            log.error("사용자 이름 JSON 파싱 실패: {}", e.getMessage(), e);
            throw new RuntimeException("사용자 이름 JSON 파싱에 실패했습니다.", e);
        }
    }

    // 사용자 등록을 완료하는 메서드 (registerUser)
    public void registerUser(RegistrationRequest request, HttpSession session) {
        try {
            String username = request.getUsername(); // 세션 ID 대신 username 사용
            log.info("사용자 이름: {}", username);  // username 로깅

            byte[] expectedChallenge = challengeService.getChallenge(username);
            log.info("Redis에서 가져온 챌린지: {}", expectedChallenge != null ? Base64.getUrlEncoder().encodeToString(expectedChallenge) : "null");

            if (expectedChallenge == null) {
                log.error("Redis에서 챌린지를 찾을 수 없습니다. 사용자 이름: {}", username);
                throw new IllegalArgumentException("등록 요청에 대한 챌린지를 찾을 수 없습니다.");
            }

            // 클라이언트에서 전송된 clientDataJSON에서 챌린지 추출
            byte[] clientDataJSON = request.getCredential().getResponse().getClientDataJSON();
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode clientData = objectMapper.readTree(new String(clientDataJSON));
            String clientChallenge = clientData.get("challenge").asText();
            log.info("클라이언트에서 받은 챌린지 (Base64): {}", clientChallenge);

            // Base64로 인코딩된 챌린지를 디코딩하여 비교 (Base64Util 사용)
            byte[] decodedClientChallenge = Base64Util.fromBase64Url(clientChallenge).getBytes();
            log.info("디코딩된 클라이언트 챌린지: {}", Base64.getUrlEncoder().encodeToString(decodedClientChallenge));

            // 클라이언트에서 전송된 챌린지와 비교
            if (!Arrays.equals(expectedChallenge, decodedClientChallenge)) {
                log.error("클라이언트에서 받은 챌린지가 일치하지 않습니다. 사용자 이름: {}", username);
                throw new IllegalArgumentException("클라이언트에서 받은 챌린지가 일치하지 않습니다.");
            }

            // 등록 요청에서 PublicKeyCredential 객체를 생성
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential =
                    buildRegistrationCredential(request);

            // 사용자 등록 절차 완료
            finishRegistration(username, credential, session);
            log.info("사용자 등록 완료: {}", username);  // 사용자 등록 완료 로그

        } catch (IllegalArgumentException | JsonProcessingException | RegistrationFailedException e) {
            log.error("사용자 등록 실패: {}", e.getMessage(), e);
            throw new RuntimeException("사용자 등록에 실패했습니다.", e);
        }
    }

    // 인증 절차를 시작하는 메서드
    public AssertionRequest startAuthentication() {
        log.info("인증 절차를 시작합니다.");
        return relyingParty.startAssertion(StartAssertionOptions.builder().build());
    }

    // 사용자 인증을 완료하는 메서드
    public boolean authenticateUser(AuthenticationRequest request) {
        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential =
                    buildAuthenticationCredential(request);

            return finishAuthentication(credential);
        } catch (Exception e) {
            log.error("사용자 인증 실패: {}", e.getMessage(), e);
            return false;
        }
    }

    // JSON에서 사용자 이름을 파싱하는 메서드
    private String parseUsername(String usernameJson) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode usernameNode = objectMapper.readTree(usernameJson);
        return usernameNode.get("username").asText();
    }

    // 사용자 정보를 조회하거나 새로 생성하는 메서드
    private User getUser(String username) {
        return userRepository.findByUsername(username)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUsername(username);
                    newUser.setDisplayName(username);
                    return userRepository.save(newUser);
                });
    }

    // 랜덤한 챌린지를 생성하는 메서드
    private ByteArray generateChallenge() {
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        return new ByteArray(challenge);
    }

    // RegistrationRequest에서 PublicKeyCredential 객체를 생성하는 메서드
    private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> buildRegistrationCredential(
            RegistrationRequest request) {
        try {
            ByteArray id = new ByteArray(request.getCredential().getId().getBytes());
            ByteArray rawId = new ByteArray(request.getCredential().getRawId());
            ByteArray clientDataJSON = new ByteArray(request.getCredential().getResponse().getClientDataJSON());
            ByteArray attestationObject = new ByteArray(request.getCredential().getResponse().getAttestationObject());

            // AttestationResponse 빌드
            AuthenticatorAttestationResponse attestationResponse = AuthenticatorAttestationResponse.builder()
                    .attestationObject(attestationObject)
                    .clientDataJSON(clientDataJSON)
                    .build();

            // PublicKeyCredential 객체 생성
            return PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                    .id(id)
                    .response(attestationResponse)
                    .clientExtensionResults(request.getClientExtensionResults())
                    .build();
        } catch (IllegalArgumentException | IOException | Base64UrlException e) {
            log.error("등록 자격 증명 생성 중 오류 발생: {}", e.getMessage(), e);
            throw new RuntimeException("등록 자격 증명 생성 중 오류가 발생했습니다.", e);
        }
    }

    // AuthenticationRequest에서 PublicKeyCredential 객체를 생성하는 메서드
    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> buildAuthenticationCredential(
            AuthenticationRequest request) {
        try {
            ByteArray id = Base64Util.fromBase64Url(request.getId());
            ByteArray clientDataJSON = Base64Util.fromBase64Url(request.getAssertion().getClientDataJSON());
            ByteArray authenticatorData = Base64Util.fromBase64Url(request.getAssertion().getAuthenticatorData());
            ByteArray signature = Base64Util.fromBase64Url(request.getAssertion().getSignature());
            ByteArray userHandle = request.getAssertion().getUserHandle() != null
                    ? Base64Util.fromBase64Url(request.getAssertion().getUserHandle())
                    : null;

            // AssertionResponse 빌드
            AuthenticatorAssertionResponse assertionResponse = AuthenticatorAssertionResponse.builder()
                    .authenticatorData(authenticatorData)
                    .clientDataJSON(clientDataJSON)
                    .signature(signature)
                    .userHandle(userHandle)
                    .build();

            // PublicKeyCredential 객체 생성
            return PublicKeyCredential.<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>builder()
                    .id(id)
                    .response(assertionResponse)
                    .clientExtensionResults(request.getClientExtensionResults())
                    .type(PublicKeyCredentialType.PUBLIC_KEY)
                    .build();
        } catch (IllegalArgumentException | IOException | Base64UrlException e) {
            log.error("Base64 URL 디코딩 실패: {}", e.getMessage(), e);
            throw new RuntimeException("Base64 URL 디코딩에 실패했습니다.", e);
        }
    }

    // 사용자 등록 절차 완료 후 챌린지 삭제 (finishRegistration)
    private void finishRegistration(String username, PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential,
                                    HttpSession session) throws RegistrationFailedException {
        log.info("finishRegistration 메서드에서 사용자 이름: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        // Redis에서 챌린지를 가져옴
        byte[] savedChallengeBytes = challengeService.getChallenge(username);
        if (savedChallengeBytes == null) {
            throw new IllegalStateException("Redis에서 챌린지를 찾을 수 없습니다.");
        }
        ByteArray savedChallenge = new ByteArray(savedChallengeBytes);

        // FinishRegistrationOptions 객체 생성
        FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                .request(PublicKeyCredentialCreationOptions.builder()
                        .rp(relyingParty.getIdentity())
                        .user(UserIdentity.builder()
                                .name(user.getUsername())
                                .displayName(user.getDisplayName())
                                .id(new ByteArray(user.getId().toString().getBytes()))
                                .build())
                        .challenge(savedChallenge)
                        .pubKeyCredParams(List.of(PublicKeyCredentialParameters.builder()
                                .alg(COSEAlgorithmIdentifier.ES256)
                                .type(PublicKeyCredentialType.PUBLIC_KEY)
                                .build()))
                        .build())
                .response(credential)
                .build();

        // 등록 절차 완료 및 결과 저장
        RegistrationResult result = relyingParty.finishRegistration(options);

        // Passkey 객체를 생성하고 데이터베이스에 저장
        Passkey passkey = new Passkey();
        passkey.setCredentialId(result.getKeyId().getId().getBase64());
        passkey.setRawId(credential.getId().getBase64());
        passkey.setPublicKey(result.getPublicKeyCose().getBytes());
        passkey.setUser(user);
        passkeyRepository.save(passkey);

        log.info("사용자 {}의 등록이 완료되었습니다. Passkey ID: {}", username, passkey.getCredentialId());

        // 등록 완료 후 Redis에서 챌린지를 삭제
        challengeService.deleteChallenge(username);
        log.info("Redis에서 챌린지가 삭제되었습니다. 사용자 이름={}", username);
    }

    // 사용자 인증을 완료하는 메서드
    private boolean finishAuthentication(PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential) {
        Optional<Passkey> passkeyOpt = passkeyRepository.findById(credential.getId().getBase64());

        if (passkeyOpt.isEmpty()) {
            log.error("해당 자격 증명 ID에 대한 Passkey를 찾을 수 없습니다: {}", credential.getId().getBase64());
            return false;
        }

        Passkey passkey = passkeyOpt.get();
        User user = passkey.getUser();

        try {
            // Assertion 완료
            AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(relyingParty.startAssertion(StartAssertionOptions.builder().build()))
                    .response(credential)
                    .build());

            log.info("사용자 {}의 Assertion 결과: {}", user.getUsername(), result.isSuccess());
            return result.isSuccess();
        } catch (AssertionFailedException e) {
            log.error("Assertion 실패: {}", e.getMessage(), e);
            return false;
        }
    }

    // PublicKeyCredentialCreationOptions 객체를 Map으로 변환하는 메서드
    public Map<String, Object> convertToMap(PublicKeyCredentialCreationOptions options) {
        Map<String, Object> map = new HashMap<>();
        map.put("rp", options.getRp());
        map.put("user", options.getUser());
        map.put("challenge", options.getChallenge().getBase64());
        map.put("pubKeyCredParams", options.getPubKeyCredParams());
        return map;
    }
}
