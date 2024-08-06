import React from 'react';
import PasskeyForm from '../components/PasskeyForm';
import { usePasskey } from '../hooks/usePasskey';

const Login: React.FC = () => {
  const { authenticateWithPasskey, error } = usePasskey();

  const handleLogin = async (username: string) => {
    const success = await authenticateWithPasskey(username);
    if (success) {
      // Redirect to dashboard or update app state
      console.log('Login successful');
    }
  };

  return (
    <div className="container mx-auto mt-8 p-4">
      <h1 className="text-3xl font-bold mb-4">Login</h1>
      <PasskeyForm onSubmit={handleLogin} buttonText="Login with Passkey" />
      {error && <p className="text-red-500 mt-4">{error}</p>}
    </div>
  );
};

export default Login;