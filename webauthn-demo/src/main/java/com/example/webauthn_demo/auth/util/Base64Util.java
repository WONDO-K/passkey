package com.example.webauthn_demo.auth.util;

import com.yubico.webauthn.data.ByteArray;

import java.util.Base64;

public class Base64Util {

    // URL-safe Base64 문자열을 일반 Base64로 변환하여 바이트 배열로 디코딩 -> "=" 패딩 처리
    public static byte[] fromBase64UrlToByteArray(String base64Url) {
        String base64 = base64Url.replace('-', '+').replace('_', '/');
        return Base64.getDecoder().decode(base64);
    }

    // 일반 Base64 문자열을 URL-safe Base64로 변환하여 바이트 배열로 디코딩
    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    // 바이트 배열을 Base64 URL-safe 문자열로 변환
    public static String toBase64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // 바이트 배열을 Base64 문자열로 변환
    public static String toBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    // ByteArray를 바이트 배열로 변환
    public static byte[] toByteArray(ByteArray byteArray) {
        return byteArray.getBytes();
    }
}
