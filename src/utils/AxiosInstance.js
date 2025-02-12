import axios from 'axios';
import { refreshAccessToken, saveTokens,removeTokens,getRefreshToken } from './auth'; 

const axiosInstance = axios.create({
  baseURL: 'https://13.61.10.70/api', // Your backend API URL
  headers: {
    "Content-Type": "application/json",
  },
});

// Add the Authorization header to all requests
axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('access');
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
});

// Handle token refresh on 401 error (token expired)

axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const refreshToken = getRefreshToken();

    // Avoid refreshing token if it's a login request
    if (originalRequest.url.includes("/users/token/")) {
      return Promise.reject(error);
    }

    if (error.response && error.response.status === 401 && refreshToken) {
      try {
        const newAccessToken = await refreshAccessToken(refreshToken);
        if (newAccessToken) {
          saveTokens(newAccessToken, refreshToken);
          originalRequest.headers['Authorization'] = `Bearer ${newAccessToken}`;
          return axiosInstance(originalRequest); // Retry with new token
        }
      } catch (refreshError) {
        console.error("Token refresh failed:", refreshError);
        removeTokens();
        window.location.href = '/login'; // Redirect to login
      }
    }

    return Promise.reject(error);
  }
);


export default axiosInstance;
