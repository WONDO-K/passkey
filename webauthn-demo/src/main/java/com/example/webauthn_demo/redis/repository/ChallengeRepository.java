package com.example.webauthn_demo.redis.repository;

import com.example.webauthn_demo.redis.domain.Challenge;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ChallengeRepository extends CrudRepository<Challenge, String> {
}
