package com.example.webauthn_demo.auth.util;

import com.yubico.webauthn.data.ByteArray;

import java.util.Base64;

public class Base64Util {
    public static ByteArray fromBase64Url(String base64Url) {
        // URL-safe Base64 -> 일반 Base64로 변환
        String base64 = base64Url.replace('-', '+').replace('_', '/');
        // 패딩 추가
        base64 = base64 + "==".substring(0, (4 - base64.length() % 4) % 4);
        byte[] bytes = Base64.getDecoder().decode(base64);
        return new ByteArray(bytes);
    }
}
