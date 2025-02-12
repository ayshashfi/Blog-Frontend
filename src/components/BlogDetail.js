import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axiosInstance from "../utils/AxiosInstance";
import { toast } from "sonner";

const BlogDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [blog, setBlog] = useState(null);
  const [comments, setComments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newComment, setNewComment] = useState("");

  // Fetch blog details and comments
  const fetchBlogDetails = async () => {
    try {
      const response = await axiosInstance.get(`blogs/blogs/${id}/`);
      setBlog(response.data);
      setLoading(false);
    } catch (error) {
      setLoading(false);
      toast.error("Failed to fetch blog details.");
    }
  };

  const fetchComments = async () => {
    try {
      const response = await axiosInstance.get(`blogs/blogs/${id}/comment/`);
      setComments(response.data);
    } catch (error) {
      toast.error("Failed to fetch comments.");
    }
  };

  const handleAddComment = async (e) => {
    e.preventDefault();
    if (!newComment.trim()) {
        toast.error("Comment cannot be empty.");
        return;
    }
    try {
        const response = await axiosInstance.post(`blogs/blogs/${id}/comment/`, {
            content: newComment, // Send only the content
        });
        setComments([...comments, response.data]); // Update comment list
        setNewComment(""); // Clear input
        toast.success("Comment added successfully!");
    } catch (error) {
        toast.error("Failed to add comment.");
    }
};


  // useEffect hook for fetching data on mount
  useEffect(() => {
    fetchBlogDetails();
    fetchComments();
  }, [id]); // Dependency on `id` so that it runs when the `id` changes

  if (loading) return <p>Loading...</p>;

  if (!blog) return <p>Blog not found.</p>;

  return (
    <div className="max-w-4xl mx-auto p-6 bg-white rounded-lg shadow-lg space-y-6">
      <button
        onClick={() => navigate(-1)}
        className="bg-gray-300 text-gray-800 px-4 py-2 rounded-lg hover:bg-gray-400"
      >
        Back
      </button>
      {blog.image && (
        <img
          src={blog.image}
          alt={blog.title}
          className="w-full h-64 object-cover rounded-lg"
        />
      )}
      <h2 className="text-3xl font-semibold text-gray-800">{blog.title}</h2>
      <p className="text-gray-600">{blog.content}</p>
      {blog.attachment && (
        <a
          href={blog.attachment}
          target="_blank"
          rel="noopener noreferrer"
          className="text-blue-600 underline"
        >
          Download Attachment
        </a>
      )}

      {/* Comments Section */}
      <div className="mt-8">
        <h3 className="text-2xl font-semibold text-gray-800 mb-4">Comments</h3>
        {comments.length > 0 ? (
          <div>
            {comments.map((comment) => {
  console.log(comment); // Check the structure of the comment object
  const commentDate = new Date(comment.created_at);
  return (
    <div key={comment.id} className="bg-gray-100 p-4 mb-4 rounded-lg shadow-sm">
      <p className="text-gray-700">{comment.content}</p>
      <p className="text-sm text-gray-500 mt-2">
        <span className="font-semibold">{comment.user || "Unknown User"}</span> -{" "}
        {commentDate.toLocaleDateString()} at {commentDate.toLocaleTimeString()}
      </p>
    </div>
  );
})}
          </div>
        ) : (
          <p className="text-gray-500">No comments yet.</p>
        )}

        {/* Add Comment Form */}
        <form onSubmit={handleAddComment} className="mt-6">
          <textarea
            className="w-full border border-gray-300 rounded-lg p-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
            rows="4"
            placeholder="Write your comment here..."
            value={newComment}
            onChange={(e) => setNewComment(e.target.value)}
          />
          <button
            type="submit"
            className="mt-3 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            Add Comment
          </button>
        </form>
      </div>
    </div>
  );
};

export default BlogDetail;
