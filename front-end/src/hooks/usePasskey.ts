import { useState } from 'react';
import { api } from '../services/api';

// Base64 URL-safe 형식을 일반 Base64로 변환하는 함수
function base64UrlToBuffer(base64Url: string): ArrayBuffer {
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const paddedBase64 = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  const binaryString = window.atob(paddedBase64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// 일반 Base64 문자열을 ArrayBuffer로 변환하는 함수
function base64ToBuffer(base64: string): ArrayBuffer {
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// ArrayBuffer를 Base64 URL-safe 문자열로 변환하는 함수
function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  const base64 = btoa(binary); // 일반 Base64 인코딩
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); // URL-safe Base64로 변환
}

export const usePasskey = () => {
  const [error, setError] = useState<string | null>(null);

  const registerPasskey = async (username: string) => {
    try {
      const options = await api.post('/auth/register-options', { username });

      console.log('서버에서 받은 Response:', options);

      if (options && options.challenge && options.user && options.user.id) {
        // 서버에서 받은 challenge와 user.id 값을 적절히 변환
        // Base64 URL-safe인 경우에는 base64UrlToBuffer를 사용하고, 일반 Base64인 경우에는 base64ToBuffer를 사용
        options.challenge = base64UrlToBuffer(options.challenge); // 일반적으로 URL-safe 형식으로 변환
        options.user.id = base64ToBuffer(options.user.id); // 일반 Base64 처리

        if (options.excludeCredentials) {
          options.excludeCredentials = options.excludeCredentials.map((cred: any) => ({
            ...cred,
            id: base64ToBuffer(cred.id), // 일반 Base64 처리
          }));
        }
      }

      const credential = await navigator.credentials.create({
        publicKey: options,
      }) as PublicKeyCredential;

      console.log('Created credential:', credential);
      console.log('id:', credential.id);
      console.log('rawId:', credential.rawId);

      const payload = {
        username,
        challenge: Array.from(new Uint8Array(options.challenge)), // 서버에 challenge 보내기
        credential: {
          id: bufferToBase64Url(credential.rawId), // URL-safe Base64로 변환 후 전송
          rawId: bufferToBase64Url(credential.rawId), // URL-safe Base64로 변환 후 전송
          type: credential.type,
          response: {
            attestationObject: bufferToBase64Url((credential.response as AuthenticatorAttestationResponse).attestationObject), // URL-safe Base64로 변환 후 전송
            clientDataJSON: bufferToBase64Url((credential.response as AuthenticatorAttestationResponse).clientDataJSON), // URL-safe Base64로 변환 후 전송
          },
        },
        clientExtensionResults: {} // 빈 객체로 초기화하여 전송
      };

      console.log('Serialized data:', JSON.stringify(payload));
      console.log(payload);

      const response = await api.post('/auth/register', payload);

      // 응답 전체 구조 로그
      console.log('응답 전체 구조:', response);

      // 응답 데이터 검사
      if (response.status === '성공') {
        console.log('등록 성공:', response.data);
      } else {
        console.error('등록 실패:', response.data?.message || '알 수 없는 오류');
      }

      return true;
    } catch (err) {
      console.error('Error during registration:', err);
      setError((err as Error).message);
      return false;
    }
  };

  const authenticateWithPasskey = async (username: string) => {
    try {
        const response = await api.get('/auth/login-options');
        const options = response.data;

        console.log('Received login options:', options);

        // Ensure 'challenge' is correctly formatted as an ArrayBuffer
        if (options && options.challenge) {
            options.challenge = base64UrlToBuffer(options.challenge);

            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map((cred: any) => ({
                    ...cred,
                    id: base64ToBuffer(cred.id),
                }));
            }
        } else {
            throw new Error('Challenge is missing in the options.');
        }

        // Ensure 'options' has the 'publicKey' property and it includes the required fields
        const publicKeyOptions: PublicKeyCredentialRequestOptions = {
            challenge: options.challenge,
            allowCredentials: options.allowCredentials,
            // Add any other required fields based on your authentication needs
        };

        const credential = await navigator.credentials.get({
            publicKey: publicKeyOptions,
        }) as PublicKeyCredential;

        const payload = {
            username,
            challenge: Array.from(new Uint8Array(options.challenge)),
            credential: {
                id: bufferToBase64Url(credential.rawId),
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    authenticatorData: bufferToBase64Url((credential.response as AuthenticatorAssertionResponse).authenticatorData),
                    clientDataJSON: bufferToBase64Url((credential.response as AuthenticatorAssertionResponse).clientDataJSON),
                    signature: bufferToBase64Url((credential.response as AuthenticatorAssertionResponse).signature),
                    userHandle: (credential.response as AuthenticatorAssertionResponse).userHandle
                        ? bufferToBase64Url((credential.response as AuthenticatorAssertionResponse).userHandle as ArrayBuffer)
                        : null,
                },
            },
        };

        console.log('Serialized data:', JSON.stringify(payload));
        console.log("Sending payload:", payload);

        await api.post('/auth/login', payload);

        return true;
    } catch (err) {
        console.error('Error during authentication:', err);
        setError((err as Error).message);
        return false;
    }
};


  return { registerPasskey, authenticateWithPasskey, error };
};
