import axios from "axios";
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


export const Getwithparams = async (URL:string,params:any) => {
  try {
    const response = await axios.get(`${API_BASE_URL}${URL}`, {
      params: params
    });
    return response.data; // content 배열만 반환
  } catch (error) {
    console.error("데이터를 가져오는 중 오류가 발생했습니다!", error);
  }
};
