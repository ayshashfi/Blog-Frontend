import axios from "axios";

// Save tokens to localStorage
export const saveTokens = (accessToken, refreshToken, role) => {
  localStorage.setItem("access", accessToken);
  localStorage.setItem("refresh", refreshToken);
  localStorage.setItem("role", role); // Ensure role is stored
};


// Get access token from localStorage
export const getAccessToken = () => {
  return localStorage.getItem("access");
};

// Get refresh token from localStorage
export const getRefreshToken = () => {
  return localStorage.getItem("refresh");
};

// Remove tokens from localStorage (logout function)
export const removeTokens = () => {
  localStorage.removeItem("access");
  localStorage.removeItem("refresh");
};

// Get user role from the access token (JWT decoding)
// export const getRoleFromToken = (token) => {
//   if (!token) return null;

//   try {
//     const decoded = JSON.parse(atob(token.split('.')[1])); // Decode JWT token (base64)
//     return decoded.role; // Assuming the role is stored in the JWT payload
//   } catch (error) {
//     console.error("Error decoding token:", error);
//     return null;
//   }
// };

// Check if the user is authenticated (i.e., access token exists)
export const isAuthenticated = () => {
  const token = getAccessToken();
  return token !== null;
};

// Login function: Authenticates the user and saves the tokens
export const login = async (email, password) => {
  try {
    const response = await axios.post("http://127.0.0.1:8000/api/users/token/", {
      email,
      password,
    });

    const { access, refresh, user } = response.data; // Ensure API returns user data
    saveTokens(access, refresh, user.role); // Save tokens & role
    localStorage.setItem("user", JSON.stringify(user)); // Save user object

    return { access, refresh, user };
  } catch (error) {
    console.error("Login failed:", error);
    throw new Error("Invalid credentials");
  }
};


// Logout function
export const logout = () => {
  removeTokens(); // Remove tokens from localStorage
};
 
// Refresh access token using the refresh token
export const refreshAccessToken = async (refreshToken) => {
  try {
    const response = await axios.post('http://127.0.0.1:8000/api/users/token/refresh/', {
      refresh: refreshToken,
    });
    const { access } = response.data; // Extract new access token from the response
    return access;
  } catch (error) {
    console.error('Error refreshing token:', error);
    return null; // Return null if refresh fails
  }
};
