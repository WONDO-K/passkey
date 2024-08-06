declare module '@webauthn/client' {
    export function solveRegistrationChallenge(options: any): Promise<any>;
    export function solveLoginChallenge(options: any): Promise<any>;
  }
  