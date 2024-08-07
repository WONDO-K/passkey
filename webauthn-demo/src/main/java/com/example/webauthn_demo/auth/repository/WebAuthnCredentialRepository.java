package com.example.webauthn_demo.auth.repository;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.stereotype.Repository;

import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Repository
public class WebAuthnCredentialRepository implements CredentialRepository {

    private final PasskeyRepository passkeyRepository;

    public WebAuthnCredentialRepository(PasskeyRepository passkeyRepository) {
        this.passkeyRepository = passkeyRepository;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return passkeyRepository.findByUserUsername(username).stream()
                .map(passkey -> {
                    byte[] credentialIdBytes = Base64.getDecoder().decode(passkey.getCredentialId());
                    return PublicKeyCredentialDescriptor.builder()
                            .id(new ByteArray(credentialIdBytes))
                            .build();
                })
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return passkeyRepository.findByUserUsername(username).stream()
                .findFirst()
                .map(passkey -> new ByteArray(passkey.getUser().getId().toString().getBytes()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return passkeyRepository.findByUserIdBytes(userHandle.getBytes())
                .map(passkey -> passkey.getUser().getUsername());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return passkeyRepository.findById(credentialId.getBase64())
                .map(passkey -> RegisteredCredential.builder()
                        .credentialId(credentialId)
                        .userHandle(userHandle)
                        .publicKeyCose(new ByteArray(passkey.getPublicKey()))
                        .build());
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return passkeyRepository.findById(credentialId.getBase64())
                .map(passkey -> RegisteredCredential.builder()
                        .credentialId(credentialId)
                        .userHandle(new ByteArray(passkey.getUser().getId().toString().getBytes()))
                        .publicKeyCose(new ByteArray(passkey.getPublicKey()))
                        .build())
                .map(Set::of)
                .orElse(Set.of());
    }
}