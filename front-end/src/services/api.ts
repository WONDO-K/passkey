const API_BASE_URL = 'http://localhost:8080/api';

export const api = {
  async post(endpoint: string, data: any) {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
      if (!response.ok) {
        throw new Error('Network response was not ok 1');
      }
      const result = await response.json();
      console.log('API response data:', result); // 서버 응답 확인
      return result;
    } catch (err) {
      console.error('API post error:', err);
      throw err;
    }
  },

  async get(endpoint: string) {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`);
      if (!response.ok) {
        throw new Error('Network response was not ok 2');
      }
      const result = await response.json();
      console.log('API response data:', result); // 서버 응답 확인
      return result;
    } catch (err) {
      console.error('API get error:', err);
      throw err;
    }
  },
};
