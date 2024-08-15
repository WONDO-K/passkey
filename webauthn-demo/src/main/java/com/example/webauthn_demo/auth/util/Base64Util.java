package com.example.webauthn_demo.auth.util;

import java.util.Base64;

public class Base64Util {

    // URL-safe Base64 문자열을 일반 Base64로 변환하여 바이트 배열로 디코딩
    public static byte[] fromBase64UrlToByteArray(String base64Url) {
        try {
            // URL-safe Base64 문자열을 일반 Base64 형식으로 변환
            String base64 = base64Url.replace('-', '+').replace('_', '/');

            // Base64 문자열의 길이가 4의 배수가 아니면 '=' 패딩 추가
            int paddingLength = (4 - base64.length() % 4) % 4;
            base64 = base64 + "=".repeat(paddingLength);

            // 디코딩 시도
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            // 디코딩 중 예외 발생 시 사용자 정의 예외 처리
            throw new IllegalArgumentException("Base64 URL에서 바이트 배열로 변환 실패. 잘못된 Base64 입력: " + base64Url, e);
        }
    }

    // 일반 Base64 문자열을 바이트 배열로 디코딩
    public static byte[] fromBase64(String base64) {
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            // 디코딩 중 예외 발생 시 사용자 정의 예외 처리
            throw new IllegalArgumentException("Base64 문자열에서 바이트 배열로 변환 실패. 잘못된 Base64 입력: " + base64, e);
        }
    }

    // 바이트 배열을 Base64 URL-safe 문자열로 변환
    public static String toBase64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // 바이트 배열을 일반 Base64 문자열로 변환
    public static String toBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    // Base64 URL-safe 문자열에서 패딩 처리된 문자열을 일반 Base64로 변환하여 바이트 배열로 디코딩
    public static byte[] fromBase64UrlWithPadding(String base64Url) {
        try {
            // URL-safe Base64 문자열을 일반 Base64 형식으로 변환
            String base64 = base64Url.replace('-', '+').replace('_', '/');

            // Base64 문자열의 길이가 4의 배수가 아니면 '=' 패딩 추가
            int paddingLength = (4 - base64.length() % 4) % 4;
            base64 = base64 + "=".repeat(paddingLength);

            // 디코딩 시도
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            // 디코딩 중 예외 발생 시 사용자 정의 예외 처리
            throw new IllegalArgumentException("Base64 URL에서 바이트 배열로 변환 실패. 잘못된 Base64 입력: " + base64Url, e);
        }
    }
}
