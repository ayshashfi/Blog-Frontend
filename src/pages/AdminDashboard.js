import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axiosInstance from "../utils/AxiosInstance";
import { toast } from "sonner";

const AdminDashboard = () => {
  const [blogs, setBlogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingBlog, setEditingBlog] = useState(null);
  const [editTitle, setEditTitle] = useState("");
  const [editContent, setEditContent] = useState("");
  const [editImage, setEditImage] = useState(null);
  const [editImagePreview, setEditImagePreview] = useState(null);
  const [editAttachment, setEditAttachment] = useState(null);
  const [existingAttachment, setExistingAttachment] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    // const token = localStorage.getItem("access_token"); // Get token from storage
    // if (!token) {
    //   toast.error("You need to log in first!");
    //   navigate("/login"); // Redirect to login page
    //   return;
    // }
    fetchBlogs();
  }, []);

  const fetchBlogs = async () => {
    try {
      const response = await axiosInstance.get("blogs/blogs/");
      console.log("Fetched Blogs:", response.data); // Debugging
      setBlogs(response.data);
      setLoading(false);
    } catch (error) {
      console.error("Fetch Error:", error);
      setLoading(false);
      toast.error("Failed to fetch blogs.");
    }
  };

  const handleDelete = async (id) => {
    try {
      await axiosInstance.delete(`blogs/blogs/${id}/`);
      toast.success("Blog deleted successfully!");
      fetchBlogs();
    } catch (error) {
      toast.error("Failed to delete blog.");
    }
  };

  const openEditModal = (blog) => {
    setEditingBlog(blog);
    setEditTitle(blog.title);
    setEditContent(blog.content);
    setEditImage(null);
    setEditImagePreview(blog.image);
    setEditAttachment(null);
    setExistingAttachment(blog.attachment); // Ensure this is correctly set
  };

  const closeEditModal = () => {
    setEditingBlog(null);
    setEditTitle("");
    setEditContent("");
    setEditImage(null);
    setEditImagePreview(null);
    setEditAttachment(null);
    setExistingAttachment(null);
  };

  const handleEditSubmit = async () => {
    try {
      const formData = new FormData();
      formData.append("title", editTitle);
      formData.append("content", editContent);
      if (editImage) formData.append("image", editImage);
      if (editAttachment) formData.append("attachment", editAttachment);

      await axiosInstance.put(`blogs/blogs/${editingBlog.id}/`, formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      toast.success("Blog updated successfully!");
      closeEditModal();
      fetchBlogs();
    } catch (error) {
      console.error("Edit Error:", error);
      toast.error("Failed to update blog.");
    }
  };

  return (
    <div className="max-w-7xl mx-auto p-6 bg-white rounded-lg shadow-lg space-y-6">
      <h2 className="text-3xl font-semibold text-center text-gray-800">Admin Dashboard</h2>

      <div className="flex justify-end">
        <button
          onClick={() => navigate("/create-blog")}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          Create Blog
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mt-6">
        {loading ? (
          <p>Loading...</p>
        ) : blogs.length > 0 ? (
          blogs.map((blog) => (
            <div
              key={blog.id}
              className="bg-gray-100 p-4 rounded-lg shadow-md flex flex-col space-y-4"
            >
              {blog.image && (
                <img
                  src={blog.image}
                  alt={blog.title}
                  className="w-full h-40 object-cover rounded-lg"
                />
              )}
              <h3 className="text-xl font-semibold text-gray-800">{blog.title}</h3>
              <p className="text-gray-600 line-clamp-1">{blog.content}</p>
              <div className="flex space-x-4">
                <button
                  onClick={() => openEditModal(blog)}
                  className="bg-yellow-500 text-white px-3 py-1 rounded-lg hover:bg-yellow-600"
                >
                  Edit
                </button>
                <button
                  onClick={() => handleDelete(blog.id)}
                  className="bg-red-500 text-white px-3 py-1 rounded-lg hover:bg-red-600"
                >
                  Delete
                </button>
                <button
                  onClick={() => navigate(`/blogs/${blog.id}`)}
                  className="bg-blue-500 text-white px-3 py-1 rounded-lg hover:bg-blue-600"
                >
                  Read More
                </button>
              </div>
            </div>
          ))
        ) : (
          <p className="text-center text-gray-600">No blogs found.</p>
        )}
      </div>

      {editingBlog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-8 rounded-lg shadow-lg space-y-4 w-full max-w-2xl">
            <h3 className="text-xl font-semibold">Edit Blog</h3>
            {editImagePreview && (
              <img src={editImagePreview} alt="Preview" className="w-full h-40 object-cover rounded-lg" />
            )}
            <input
              type="text"
              value={editTitle}
              onChange={(e) => setEditTitle(e.target.value)}
              placeholder="Blog Title"
              className="w-full px-4 py-2 border rounded-lg"
            />
            <textarea
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              placeholder="Blog Content"
              rows="6"
              className="w-full px-4 py-2 border rounded-lg"
            />
            <input
              type="file"
              onChange={(e) => {
                setEditImage(e.target.files[0]);
                setEditImagePreview(URL.createObjectURL(e.target.files[0]));
              }}
              className="w-full px-4 py-2 border rounded-lg"
            />
            <input
              type="file"
              onChange={(e) => setEditAttachment(e.target.files[0])}
              className="w-full px-4 py-2 border rounded-lg"
            />
            {existingAttachment && !editAttachment && (
              <p className="text-gray-700">
                Existing Attachment:{" "}
                <a
                  href={existingAttachment}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 underline"
                >
                  View Attachment
                </a>
              </p>
            )}
            {editAttachment && <p className="text-gray-700">Selected Attachment: {editAttachment.name}</p>}
            <div className="flex justify-end space-x-4">
              <button onClick={closeEditModal} className="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600">Cancel</button>
              <button onClick={handleEditSubmit} className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Save Changes</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminDashboard;
