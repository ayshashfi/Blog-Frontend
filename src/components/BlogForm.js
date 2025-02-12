import React, { useState, useEffect } from "react";

const BlogForm = ({ selectedBlog, onSubmit }) => {
  const [formData, setFormData] = useState({
    title: "",
    content: "",
    image: null,
    attachment: null,
  });

  useEffect(() => {
    if (selectedBlog) {
      setFormData({
        title: selectedBlog.title,
        content: selectedBlog.content,
        image: null, // Ideally, you'd fetch the existing image URL if needed
        attachment: null,
      });
    } else {
      setFormData({
        title: "",
        content: "",
        image: null,
        attachment: null,
      });
    }
  }, [selectedBlog]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleFileChange = (e) => {
    const { name, files } = e.target;
    setFormData({ ...formData, [name]: files[0] });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const data = new FormData();
    data.append("title", formData.title);
    data.append("content", formData.content);

    if (formData.image) {
      data.append("image", formData.image);
    }

    if (formData.attachment) {
      data.append("attachment", formData.attachment);
    }

    onSubmit(data);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="title" className="block text-sm font-medium text-gray-700">
          Title
        </label>
        <input
          type="text"
          id="title"
          name="title"
          value={formData.title}
          onChange={handleChange}
          className="w-full mt-1 px-4 py-2 border border-gray-300 rounded-lg"
          required
        />
      </div>

      <div>
        <label htmlFor="content" className="block text-sm font-medium text-gray-700">
          Content
        </label>
        <textarea
          id="content"
          name="content"
          value={formData.content}
          onChange={handleChange}
          rows="4"
          className="w-full mt-1 px-4 py-2 border border-gray-300 rounded-lg"
          required
        ></textarea>
      </div>

      <div>
        <label htmlFor="image" className="block text-sm font-medium text-gray-700">
          Upload Image
        </label>
        <input
          type="file"
          id="image"
          name="image"
          accept="image/*"
          onChange={handleFileChange}
          className="mt-1"
        />
      </div>

      <div>
        <label htmlFor="attachment" className="block text-sm font-medium text-gray-700">
          Upload Attachment (Optional)
        </label>
        <input
          type="file"
          id="attachment"
          name="attachment"
          accept=".pdf,.doc,.docx"
          onChange={handleFileChange}
          className="mt-1"
        />
      </div>

      <button
        type="submit"
        className="w-full py-2 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
      >
        {selectedBlog ? "Update Blog" : "Create Blog"}
      </button>
    </form>
  );
};

export default BlogForm;
