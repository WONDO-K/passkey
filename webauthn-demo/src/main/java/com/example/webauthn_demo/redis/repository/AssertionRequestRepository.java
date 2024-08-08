package com.example.webauthn_demo.redis.repository;

import com.example.webauthn_demo.redis.domain.AssertionRequest;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AssertionRequestRepository extends CrudRepository<AssertionRequest, String> {
}
