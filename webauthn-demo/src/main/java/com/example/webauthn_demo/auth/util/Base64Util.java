package com.example.webauthn_demo.auth.util;

import com.yubico.webauthn.data.ByteArray;

import java.util.Base64;

public class Base64Util {

    // URL-safe Base64 -> 일반 Base64로 변환하여 byte[]로 반환
    public static byte[] fromBase64Url(String base64Url) {
        String base64 = base64Url.replace('-', '+').replace('_', '/');
        return Base64.getDecoder().decode(base64);
    }

    // byte[] -> URL-safe Base64 문자열로 변환
    public static String toBase64Url(byte[] bytes) {
        String base64 = Base64.getEncoder().encodeToString(bytes);
        return base64.replace('+', '-').replace('/', '_').replaceAll("=+$", "");
    }

    // 일반 Base64 -> byte[]로 변환
    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    // byte[] -> 일반 Base64로 변환
    public static String toBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    // ByteArray -> 일반 Base64 문자열로 변환 (사용할 수 있는 경우)
    public static String toBase64(ByteArray byteArray) {
        return Base64.getEncoder().encodeToString(byteArray.getBytes());
    }

    // 일반 Base64 문자열을 ByteArray로 변환 (사용할 수 있는 경우)
    public static ByteArray fromBase64ToByteArray(String base64) {
        return new ByteArray(Base64.getDecoder().decode(base64));
    }
}
