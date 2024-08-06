import { useState } from 'react';
import { api } from '../services/api';

function base64UrlToBuffer(base64Url: string): ArrayBuffer {
  console.log('base64Url received:', base64Url);
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  console.log('Converted ArrayBuffer:', bytes.buffer);
  return bytes.buffer;
}

export const usePasskey = () => {
  const [error, setError] = useState<string | null>(null);

  const registerPasskey = async (username: string) => {
    try {
      const options = await api.post('/auth/register-options', { username });

      console.log('서버에서 받은 Response:', options);

      if (options && options.challenge && options.user && options.user.id) {
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

        console.log('Created credential:', credential);

        const payload = {
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
        };

        console.log('Serialized data:', JSON.stringify(payload));

        await api.post('/auth/register', payload);

        return true;
      } else {
        throw new Error('Invalid registration options from server');
      }
    } catch (err) {
      console.error('Error during registration:', err);
      setError((err as Error).message);
      return false;
    }
  };

  const authenticateWithPasskey = async (username: string) => {
    try {
      const options = await api.get('/auth/login-options');

      console.log('Received login options:', options);

      if (options && options.challenge) {
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
      console.error('Error during authentication:', err);
      setError((err as Error).message);
      return false;
    }
  };

  return { registerPasskey, authenticateWithPasskey, error };
};



