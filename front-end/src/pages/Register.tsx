import React from 'react';
import PasskeyForm from '../components/PasskeyForm';
import { usePasskey } from '../hooks/usePasskey';

const Register: React.FC = () => {
  const { registerPasskey, error } = usePasskey();

  const handleRegister = async (username: string) => {
    const success = await registerPasskey(username);
    if (success) {
      // Redirect to login page or update app state
      console.log('Registration successful');
    }
  };

  return (
    <div className="container mx-auto mt-8 p-4">
      <h1 className="text-3xl font-bold mb-4">Register</h1>
      <PasskeyForm onSubmit={handleRegister} buttonText="Register with Passkey" />
      {error && <p className="text-red-500 mt-4">{error}</p>}
    </div>
  );
};

export default Register;