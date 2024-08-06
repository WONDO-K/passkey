import { useState } from 'react';
import { api } from '../services/api';

function base64UrlToBuffer(base64Url: string): ArrayBuffer {
  console.log('base64Url received:', base64Url);  // 추가된 로그
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  console.log('Converted ArrayBuffer:', bytes.buffer);
  return bytes.buffer;
}

export const usePasskey = () => {
  const [error, setError] = useState<string | null>(null);

  const registerPasskey = async (username: string) => {
    try {
      const { data: options } = await api.post('/auth/register-options', { username });

       // 로그 추가: 서버로부터 받은 options 데이터 확인
       console.log('Received registration options:', options);


      // Check if options and its properties are properly defined
      if (options && options.challenge && options.user && options.user.id) {
        // Convert necessary options to ArrayBuffer
        options.challenge = base64UrlToBuffer(options.challenge);
        options.user.id = base64UrlToBuffer(options.user.id);
        if (options.excludeCredentials) {
          options.excludeCredentials = options.excludeCredentials.map((cred: any) => ({
            ...cred,
            id: base64UrlToBuffer(cred.id),
          }));
        }

        const credential = await navigator.credentials.create({
          publicKey: options,
        }) as PublicKeyCredential;

        await api.post('/auth/register', {
          username,
          credential: {
            id: credential.id,
            rawId: Array.from(new Uint8Array(credential.rawId)),
            type: credential.type,
            response: {
              attestationObject: Array.from(new Uint8Array((credential.response as AuthenticatorAttestationResponse).attestationObject)),
              clientDataJSON: Array.from(new Uint8Array((credential.response as AuthenticatorAttestationResponse).clientDataJSON)),
            },
          },
        });

        return true;
      } else {
        throw new Error('Invalid registration options from server');
      }
    } catch (err) {
      setError((err as Error).message);
      return false;
    }
  };

  const authenticateWithPasskey = async (username: string) => {
    try {
      const { data: options } = await api.get('/auth/login-options');

      // Check if options and its properties are properly defined
      if (options && options.challenge) {
        // Convert necessary options to ArrayBuffer
        options.challenge = base64UrlToBuffer(options.challenge);
        if (options.allowCredentials) {
          options.allowCredentials = options.allowCredentials.map((cred: any) => ({
            ...cred,
            id: base64UrlToBuffer(cred.id),
          }));
        }

        const credential = await navigator.credentials.get({
          publicKey: options,
        }) as PublicKeyCredential;
    
        await api.post('/auth/login', {
          username,
          credential: {
            id: credential.id,
            rawId: Array.from(new Uint8Array(credential.rawId)),
            type: credential.type,
            response: {
              authenticatorData: Array.from(new Uint8Array((credential.response as AuthenticatorAssertionResponse).authenticatorData)),
              clientDataJSON: Array.from(new Uint8Array((credential.response as AuthenticatorAssertionResponse).clientDataJSON)),
              signature: Array.from(new Uint8Array((credential.response as AuthenticatorAssertionResponse).signature)),
              userHandle: (credential.response as AuthenticatorAssertionResponse).userHandle 
                ? Array.from(new Uint8Array((credential.response as AuthenticatorAssertionResponse).userHandle as ArrayBuffer))
                : null,
            },
          },
        });
    
        return true;
      } else {
        throw new Error('Invalid authentication options from server');
      }
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unknown error occurred');
      }
      return false;
    }
  };

  return { registerPasskey, authenticateWithPasskey, error };
};
