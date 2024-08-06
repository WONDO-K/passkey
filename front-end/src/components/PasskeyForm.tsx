import React from 'react';

interface PasskeyFormProps {
  onSubmit: (username: string) => void;
  buttonText: string;
}

const PasskeyForm: React.FC<PasskeyFormProps> = ({ onSubmit, buttonText }) => {
  const [username, setUsername] = React.useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(username);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="username" className="block mb-2">Username:</label>
        <input
          type="text"
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full p-2 border rounded"
          required
        />
      </div>
      <button type="submit" className="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600">
        {buttonText}
      </button>
    </form>
  );
};

export default PasskeyForm;