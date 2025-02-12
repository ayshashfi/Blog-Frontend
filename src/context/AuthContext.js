import { createContext, useContext, useState, useEffect } from 'react';
import axiosInstance from '../utils/AxiosInstance'; // Assuming axiosInstance is properly set up

const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState(null);

  // Check if there's a saved token and role on app load
  useEffect(() => {
    const storedRole = localStorage.getItem('role');
    const storedToken = localStorage.getItem('access_token');
    if (storedToken && storedRole) {
      setUser({ role: storedRole });
    }
  }, []);

  const login = async (formData) => {
    setLoading(true);
    try {
      const response = await axiosInstance.post('/api/users/user/login/token/', formData);
      const { access_token } = response.data;

      // Step 1: Store the access token in localStorage
      localStorage.setItem('access_token', access_token);

      // Step 2: Fetch the user's role using the access token
      const roleResponse = await axiosInstance.get('/api/users/user/role/', {
        headers: { Authorization: `Bearer ${access_token}` },
      });
      const { role, username, email } = roleResponse.data;

      // Step 3: Save role and user data in localStorage
      localStorage.setItem('role', role);
      localStorage.setItem('username', username);
      localStorage.setItem('email', email);

      // Step 4: Set user state
      setUser({ role, username, email });

      return { role, username, email }; // Return data for navigation
    } catch (error) {
      console.error('Login failed:', error);
      throw new Error(error.response?.data?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    // Clear the stored token and role upon logout
    localStorage.removeItem('access_token');
    localStorage.removeItem('role');
    localStorage.removeItem('username');
    localStorage.removeItem('email');
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ login, loading, user, logout }}>
      {children}
    </AuthContext.Provider>
  );
};