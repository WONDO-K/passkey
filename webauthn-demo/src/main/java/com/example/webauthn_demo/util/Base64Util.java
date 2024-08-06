package com.example.webauthn_demo.util;

import com.yubico.webauthn.data.ByteArray;

import java.util.Base64;

public class Base64Util {
    public static ByteArray fromBase64Url(String base64Url) {
        byte[] bytes = Base64.getUrlDecoder().decode(base64Url);
        return new ByteArray(bytes);
    }
}