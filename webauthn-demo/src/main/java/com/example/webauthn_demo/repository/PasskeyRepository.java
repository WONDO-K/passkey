package com.example.webauthn_demo.repository;

import com.example.webauthn_demo.model.Passkey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface PasskeyRepository extends JpaRepository<Passkey, String> {
    List<Passkey> findByUserUsername(String username);

    @Query("SELECT p FROM Passkey p WHERE p.user.id = :userId")
    Optional<Passkey> findByUserIdBytes(byte[] userId);
}