import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axiosInstance from "../utils/AxiosInstance";
import { toast } from "sonner";

const CreateBlog = () => {
  const [blogData, setBlogData] = useState({ title: "", content: "" });
  const [image, setImage] = useState(null);
  const [attachments, setAttachments] = useState([]);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setBlogData({ ...blogData, [e.target.name]: e.target.value });
  };

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImage(file);
    }
  };

  const handleAttachmentsChange = (e) => {
    setAttachments(Array.from(e.target.files));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append("title", blogData.title);
    formData.append("content", blogData.content);
    if (image) formData.append("image", image);

    if (attachments.length > 0) {
      attachments.forEach((file) => {
        formData.append("attachment", file);
      });
    }

    try {
      await axiosInstance.post("blogs/blogs/", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });
      toast.success("Blog created successfully!");
      navigate("/admin-dashboard");
    } catch (error) {
      toast.error("Failed to create blog.");
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-2xl font-semibold text-center text-gray-800">
        Create Blog
      </h2>
      <form onSubmit={handleSubmit} className="space-y-4 mt-6">
        <div>
          <label className="block text-gray-600 font-medium">Title</label>
          <input
            type="text"
            name="title"
            value={blogData.title}
            onChange={handleChange}
            required
            className="w-full border rounded-lg px-4 py-2 mt-2"
          />
        </div>
        <div>
          <label className="block text-gray-600 font-medium">Content</label>
          <textarea
            name="content"
            value={blogData.content}
            onChange={handleChange}
            required
            className="w-full border rounded-lg px-4 py-2 mt-2"
            rows="6"
          />
        </div>
        <div>
          <label className="block text-gray-600 font-medium">Image</label>
          <input
            type="file"
            accept="image/*"
            onChange={handleImageChange}
            className="w-full border rounded-lg px-4 py-2 mt-2"
          />
          {image && (
            <div className="mt-2">
              <p className="text-sm text-gray-500">Selected Image:</p>
              <img
                src={URL.createObjectURL(image)}
                alt="Selected"
                className="mt-2 w-32 h-32 object-cover rounded-lg shadow"
              />
            </div>
          )}
        </div>
        <div>
          <label className="block text-gray-600 font-medium">Attachments</label>
          <input
            type="file"
            multiple
            onChange={handleAttachmentsChange}
            className="w-full border rounded-lg px-4 py-2 mt-2"
          />
          {attachments.length > 0 && (
            <div className="mt-2">
              <p className="text-sm text-gray-500">Selected Attachments:</p>
              <ul className="list-disc pl-5 text-sm text-gray-700">
                {attachments.map((file, index) => (
                  <li key={index}>{file.name}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
        <div className="flex justify-end">
          <button
            type="submit"
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            Submit
          </button>
        </div>
      </form>
    </div>
  );
};

export default CreateBlog;
