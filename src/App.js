import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import Navbar from "./components/Navbar";
import Footer from "./components/Footer";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import AdminDashboard from "./pages/AdminDashboard";
import UserDashboard from "./pages/UserDashboard";
import Home from "./pages/Home";
import AdminLogin from "./pages/AdminLogin";
import CreateBlog from "./pages/CreateBlog";
import BlogDetail from "./components/BlogDetail";
import { useLocation } from "react-router-dom";
import { Toaster } from "sonner";

const LocationWrapper = () => {
  const location = useLocation();
  const isAuthPage = ["/login", "/register", "/adminlogin", "/"].includes(location.pathname);
  return <>{!isAuthPage && <Navbar />}</>;
};

const App = () => {
  return (
    <Router>
      <AuthProvider>
        <LocationWrapper />
        <Toaster richColors position="top-right" />
        <div className="min-h-screen">
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/adminlogin" element={<AdminLogin />} />
            <Route path="/register" element={<Signup />} />
            <Route path="/blogs/:id" element={<BlogDetail />} />
            <Route path="/admin-dashboard" element={<AdminDashboard />} />
            <Route path="/user-dashboard" element={<UserDashboard />} />
            <Route path="/create-blog" element={<CreateBlog />} />

          </Routes>
        </div>
        <Footer />
      </AuthProvider>
    </Router>
  );
};

export default App;