import React, { useEffect, useState } from "react";
import axiosInstance from "../utils/AxiosInstance";
import { useNavigate } from "react-router-dom";
import "../styles/Home.css";

const Home = () => {
  const [blogs, setBlogs] = useState([]);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchBlogs = async () => {
      try {
        const response = await axiosInstance.get("blogs/blogs/");
        setBlogs(response.data);
      } catch (err) {
        console.error("Error fetching blogs:", err);
        setError("Failed to load blogs. Please try again later.");
      }
    };

    fetchBlogs();
  }, []);

  const handleReadMore = () => {
    navigate("/login");
  };

  const formatDate = (dateString) => {
    const options = { year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit" };
    return new Date(dateString).toLocaleDateString(undefined, options);
  };

  return (
    <div className="min-h-screen bg-gradient-to-r from-indigo-700 via-purple-700 to-pink-700">
      <div className="container mx-auto px-4 py-10">
        {/* Header Section */}
        <div className="flex flex-col lg:flex-row justify-between items-center mb-10">
          <div className="text-center lg:text-left">
            <h1 className="text-5xl font-extrabold text-white mb-3">
              <span className="bg-gradient-to-r from-yellow-400 via-red-500 to-pink-500 bg-clip-text text-transparent">
                Blog App
              </span>
            </h1>
            <p className="text-lg text-gray-300">
              Discover a world of insightful articles and discussions.
            </p>
          </div>
          <div className="mt-6 lg:mt-0 flex space-x-4">
            <button
              onClick={() => navigate("/login")}
              className="py-2 px-6 bg-blue-500 text-white font-semibold rounded-lg hover:bg-blue-600 transition-all"
            >
              Login
            </button>
            <button
              onClick={() => navigate("/register")}
              className="py-2 px-6 bg-green-500 text-white font-semibold rounded-lg hover:bg-green-600 transition-all"
            >
              Register
            </button>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="text-center mb-6">
            <p className="text-red-500 font-semibold">{error}</p>
          </div>
        )}

        {/* Blogs Section */}
        {/* Blogs Section */}
<section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">
  {blogs.length > 0 ? (
    blogs.map((blog) => (
      <div
        key={blog.id}
        className="bg-white p-6 rounded-xl shadow-lg hover:shadow-2xl transition-transform transform hover:-translate-y-2"
      >
        <img
          src={blog.image}
          alt={blog.title}
          className="w-full h-48 object-cover rounded-lg mb-4"
        />
        <h2 className="text-xl font-bold text-gray-800 mb-1">
          {blog.title}
        </h2>
        <p className="text-sm text-gray-500 mb-2">
          {formatDate(blog.created_at)}
        </p>
        <p className="text-gray-600 mb-4">{blog.excerpt}</p>
        
        {/* Likes Count */}
        <div className="flex items-center text-gray-700 mb-4">
          <span className="mr-2 text-red-500">❤️</span> 
          <span>{blog.likes_count} Likes</span>
        </div>

        <button
          onClick={handleReadMore}
          className="py-2 px-4 bg-indigo-500 text-white font-semibold rounded-lg hover:bg-indigo-600 transition-all"
        >
          Read more
        </button>
      </div>
    ))
  ) : (
    <p className="text-center text-gray-300 col-span-full">
      No blogs available.
    </p>
  )}
</section>

      </div>
    </div>
  );
};

export default Home;
