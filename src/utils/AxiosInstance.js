import axios from 'axios';
import { refreshAccessToken, saveTokens, removeTokens, getRefreshToken } from './auth';

const axiosInstance = axios.create({
  //baseURL: 'http://127.0.0.1:8000/api',
  baseURL: 'http://16.171.35.135/api', // Your backend API URL
  headers: {
    "Content-Type": "application/json",
  },
});

// Add the Authorization header to all requests,
//Automatically attaches the access token to all outgoing API requests.
//Ensures only authenticated requests are sent.

axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('access');
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
});

// Handle token refresh on 401 error (token expired)
//interceptors.response.use method is called for every API response
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config; //Stores the original request that failed due to an authentication error
    const refreshToken = getRefreshToken(); //Calls getRefreshToken() to retrieve the refresh token from localStorage.


    // Avoid refreshing token if it's a login request
    if (originalRequest.url.includes("/users/token/")) {
      return Promise.reject(error);
    }

    if (error.response && error.response.status === 401 && refreshToken) {       //it means the access token has expired.
      //We proceed to refresh the token only if a refresh token exists.
      try {
        const newAccessToken = await refreshAccessToken(refreshToken);  //Attempt to Refresh the Access Token
        if (newAccessToken) {                                       //If Token Refresh is Successful, Save the New Token
          saveTokens(newAccessToken, refreshToken);
          originalRequest.headers['Authorization'] = `Bearer ${newAccessToken}`; //Updates the Authorization header of the original request with the new access token.
          return axiosInstance(originalRequest); // Retry with new token
        }
      } catch (refreshError) {         //If Token Refresh Fails, Logout the User
        console.error("Token refresh failed:", refreshError);
        removeTokens();
        window.location.href = '/login'; // Redirect to login
      }
    }

    return Promise.reject(error);
  }
);


export default axiosInstance;
