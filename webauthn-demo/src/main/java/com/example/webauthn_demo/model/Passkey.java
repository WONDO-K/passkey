package com.example.webauthn_demo.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "passkeys")
public class Passkey {

    @Id
    @Column(length = 255)
    private String credentialId;

    @Lob
    @Column(columnDefinition = "BLOB")
    private byte[] publicKey;

    @Column(length = 255, nullable = false)
    private String rawId;  // rawId 필드를 추가

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}
