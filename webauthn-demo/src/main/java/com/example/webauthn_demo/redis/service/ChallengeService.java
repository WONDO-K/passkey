package com.example.webauthn_demo.redis.service;

import com.example.webauthn_demo.redis.domain.Challenge;
import com.example.webauthn_demo.redis.repository.ChallengeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ChallengeService {

    private final ChallengeRepository challengeRepository;

    // 챌린지 저장
    public void saveChallenge(String username, byte[] challenge) {
        Challenge challengeEntity = new Challenge();
        challengeEntity.setUsername(username); // username을 키로 사용
        challengeEntity.setChallenge(challenge);
        challengeRepository.save(challengeEntity);
    }

    // 챌린지 조회
    public byte[] getChallenge(String username) {
        return challengeRepository.findById(username) // username으로 조회
                .map(Challenge::getChallenge)
                .orElse(null);
    }

    // 챌린지 삭제
    public void deleteChallenge(String username) {
        challengeRepository.deleteById(username); // username으로 삭제
    }
}
