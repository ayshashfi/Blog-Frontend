import React, { useEffect, useState } from "react";
import axiosInstance from "../utils/AxiosInstance";
import { Link } from "react-router-dom";
import "../styles/Home.css";
import { toast } from "sonner";

const UserDashboard = () => {
  const [blogs, setBlogs] = useState([]);
  const [error, setError] = useState(null);
  const [user, setUser] = useState(null);

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

    const fetchUser = async () => {
      try {
        const response = await axiosInstance.get("users/user/");
        setUser(response.data);
      } catch (err) {
        console.error("Error fetching user:", err);
        setError("Failed to load user data. Please try again later.");
      }
    };

    fetchBlogs();
    fetchUser();
  }, []);

  const handleLike = async (blogId) => {
    const updatedBlogs = blogs.map((blog) => {
      if (blog.id === blogId) {
        const newLikedByUser = !blog.liked_by_user;
        return {
          ...blog,
          liked_by_user: newLikedByUser,
          likes_count: newLikedByUser ? blog.likes_count + 1 : blog.likes_count - 1,
        };
      }
      return blog;
    });

    setBlogs(updatedBlogs);

    try {
      const response = await axiosInstance.post(`blogs/blogs/${blogId}/like/`);
      if (!response.data.success) {
        throw new Error("API call failed");
      }
    } catch (error) {
      console.error("Error toggling like:", error);

      const revertedBlogs = blogs.map((blog) => {
        if (blog.id === blogId) {
          const revertedLikedByUser = !blog.liked_by_user;
          return {
            ...blog,
            liked_by_user: revertedLikedByUser,
            likes_count: revertedLikedByUser ? blog.likes_count + 1 : blog.likes_count - 1,
          };
        }
        return blog;
      });

      setBlogs(revertedBlogs);
      toast.error("Failed to update like status. Please try again.");
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-r from-indigo-700 via-purple-700 to-pink-700">
      <div className="container mx-auto px-4 py-10">
        <div className="flex justify-between items-center mb-10">
          <div className="text-center w-full">
            <h1 className="text-5xl font-extrabold text-white mb-3">
              <span className="bg-gradient-to-r from-yellow-400 via-red-500 to-pink-500 bg-clip-text text-transparent">
                Welcome, {user ? user.first_name : "User"}
              </span>
            </h1>
          </div>
        </div>

        {error && (
          <div className="text-center mb-6">
            <p className="text-red-500 font-semibold">{error}</p>
          </div>
        )}

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
                  <Link
                    to={`/blogs/${blog.id}`}
                    className="hover:text-indigo-600"
                  >
                    {blog.title}
                  </Link>
                </h2>
                <p className="text-sm text-gray-500 mb-4">
                  {new Date(blog.created_at).toLocaleDateString()} -{" "}
                  {new Date(blog.created_at).toLocaleTimeString()}
                </p>
                <p className="text-gray-600 mb-4">{blog.excerpt}</p>

                <button
                  onClick={() => handleLike(blog.id)}
                  className="py-2 px-4 font-semibold rounded-lg transition-all bg-white hover:bg-gray-100 text-indigo-700 mb-4 flex items-center justify-center"
                >
                  {blog.liked_by_user ? "👍" : "👍"}{" "}
                  <span className="ml-2">{blog.likes_count}</span>
                </button>

                <Link
                  to={`/blogs/${blog.id}`}
                  className="py-2 px-4 bg-indigo-500 text-white font-semibold rounded-lg hover:bg-indigo-600 transition-all"
                >
                  Read more
                </Link>
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

export default UserDashboard;
