package com.example.webauthn_demo.redis.service;

import com.example.webauthn_demo.redis.domain.AssertionRequest;
import com.example.webauthn_demo.redis.repository.AssertionRequestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AssertionRequestService {

    private final AssertionRequestRepository assertionRequestRepository;

    // AssertionRequest 저장
    public void saveAssertionRequest(String credentialId, byte[] requestData) {
        AssertionRequest assertionRequest = new AssertionRequest();
        assertionRequest.setCredentialId(credentialId); // credential ID를 키로 사용
        assertionRequest.setRequestData(requestData);
        assertionRequestRepository.save(assertionRequest);
    }

    // AssertionRequest 조회
    public byte[] getAssertionRequest(String credentialId) {
        return assertionRequestRepository.findById(credentialId) // credential ID로 조회
                .map(AssertionRequest::getRequestData)
                .orElse(null);
    }

    // AssertionRequest 삭제
    public void deleteAssertionRequest(String credentialId) {
        assertionRequestRepository.deleteById(credentialId); // credential ID로 삭제
    }
}
