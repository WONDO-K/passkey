import { useState } from 'react';
import { api } from '../services/api';

// Base64 URL-safe 형식을 일반 Base64로 변환한 후 ArrayBuffer로 변환하는 함수
function base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
  // Base64 URL-safe 문자열을 일반 Base64로 변환
  const base64 = base64Url
    .replace(/-/g, '+')   // '-'를 '+'로
    .replace(/_/g, '/');  // '_'를 '/'로

  // 패딩 추가 (필요한 경우)
  const paddedBase64 = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');

  // Base64 문자열을 binary string으로 디코딩
  const binaryString = window.atob(paddedBase64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// ArrayBuffer를 Base64 URL-safe 문자열로 변환하는 함수
function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  const base64 = btoa(binary);

  // URL-safe Base64로 변환 (패딩 제거)
  return base64
    .replace(/\+/g, '-')   // '+'를 '-'로
    .replace(/\//g, '_')   // '/'를 '_'로
    .replace(/=+$/, '');   // 패딩 제거
}

// ArrayBuffer를 byte[]로 변환하는 함수
function arrayBufferToByteArray(buffer: ArrayBuffer): number[] {
  return Array.from(new Uint8Array(buffer));
}

export const usePasskey = () => {
  const [error, setError] = useState<string | null>(null);

  const registerPasskey = async (username: string) => {
    try {
      const options = await api.post('/auth/register-options', { username });

      console.info('서버에서 받은 응답:', options);

      if (options && options.challenge && options.user && options.user.id) {
        options.challenge = base64UrlToArrayBuffer(options.challenge);
        options.user.id = base64UrlToArrayBuffer(options.user.id);

        if (options.excludeCredentials) {
          options.excludeCredentials = options.excludeCredentials.map((cred: { id: string }) => ({
            ...cred,
            id: base64UrlToArrayBuffer(cred.id),
          }));
        }
      }

      const credential = await navigator.credentials.create({
        publicKey: options,
      }) as PublicKeyCredential;

      console.log('credential', credential);

      const payload = {
        username,
        challenge: arrayBufferToByteArray(options.challenge),
        credential: {
          id: base64UrlEncode(credential.rawId),
          rawId: base64UrlEncode(credential.rawId),
          type: credential.type,
          response: {
            attestationObject: base64UrlEncode((credential.response as AuthenticatorAttestationResponse).attestationObject),
            clientDataJSON: base64UrlEncode((credential.response as AuthenticatorAttestationResponse).clientDataJSON),
          },
        },
        clientExtensionResults: {}
      };

      console.info('직렬화된 데이터:', JSON.stringify(payload));

      const response = await api.post('/auth/register', payload);

      console.info('응답 전체 구조:', response);

      if (response.status === '성공') {
        console.info('등록 성공:', response.data);
      } else {
        console.error('등록 실패:', response.data?.message || '알 수 없는 오류');
      }

      return true;
    } catch (err) {
      console.error('등록 중 오류 발생:', err);
      setError((err as Error).message);
      return false;
    }
  };

  const authenticateWithPasskey = async (username: string) => {
    try {
      const response = await api.get('/auth/login-options');
      console.info('응답:', response);

      const options = response.publicKeyCredentialRequestOptions;

      if (!options) {
        throw new Error('PublicKeyCredentialRequestOptions이 응답에 없습니다.');
      }

      if (options.challenge) {
        options.challenge = base64UrlToArrayBuffer(options.challenge);

        if (options.allowCredentials && options.allowCredentials.length > 0) {
          options.allowCredentials = options.allowCredentials.map((cred: { id: string }) => ({
            ...cred,
            id: base64UrlToArrayBuffer(cred.id),
          }));
        } else {
          options.allowCredentials = [];
        }
      } else {
        throw new Error('챌린지가 옵션에 없습니다.');
      }

      const publicKeyOptions: PublicKeyCredentialRequestOptions = {
        challenge: options.challenge,
        allowCredentials: options.allowCredentials,
        rpId: options.rpId || 'localhost',
        timeout: options.timeout || 60000,
        userVerification: options.userVerification || 'preferred',
        extensions: {}
      };

      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions,
      }) as PublicKeyCredential;

      console.log('credential', credential);

      const payload = {
        username,
        challenge: base64UrlEncode(options.challenge),
        credential: {
          id: base64UrlEncode(credential.rawId),
          rawId: base64UrlEncode(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: base64UrlEncode((credential.response as AuthenticatorAssertionResponse).authenticatorData),
            clientDataJSON: base64UrlEncode((credential.response as AuthenticatorAssertionResponse).clientDataJSON),
            signature: base64UrlEncode((credential.response as AuthenticatorAssertionResponse).signature),
          },
        },
      };

      console.info('직렬화된 데이터:', JSON.stringify(payload));
      console.info('보낼 데이터:', payload);

      const Data = {
        username: payload.username,
        id: payload.credential.id,
        rawId: payload.credential.rawId,
        assertion: {
          clientDataJSON: payload.credential.response.clientDataJSON,
          authenticatorData: payload.credential.response.authenticatorData,
          signature: payload.credential.response.signature,
        },
        clientExtensionResults: {},
        challenge: base64UrlEncode(options.challenge) // Base64 URL-safe로 인코딩된 챌린지 값
      };

      console.info('전송 데이터:', Data);

      await api.post('/auth/login', Data);

      return true;
    } catch (err) {
      console.error('인증 중 오류 발생:', err);
      setError((err as Error).message);
      return false;
    }
  };

  return { registerPasskey, authenticateWithPasskey, error };
};
