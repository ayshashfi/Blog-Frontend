import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Navbar = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = (e) => {
    e.preventDefault(); // Prevent default action

    // Clear local storage to remove tokens
    localStorage.removeItem('access');
    localStorage.removeItem('refresh');
    localStorage.removeItem("token"); 

   

    // Redirect to login page and replace the current history state
    navigate('/login', { replace: true });
  };

  return (
    <nav className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white p-5 shadow-md">
      <div className="container mx-auto flex justify-between items-center">
        <Link to="/" className="text-4xl font-bold tracking-tight text-white hover:text-gray-200 transition-all">
          BlogApp
        </Link>
        <div className="flex items-center space-x-8">
          {/* Logout Button */}
          <button
            onClick={handleLogout}
            className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md transition-all"
          >
            Logout
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
