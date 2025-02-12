import React from "react";

const BlogList = ({ blogs, onEdit, onDelete }) => {
  return (
    <div className="blog-list space-y-4">
      <h3 className="text-2xl font-semibold text-gray-800 mb-4">All Blogs</h3>
      {blogs.length === 0 ? (
        <p className="text-gray-600">No blogs available.</p>
      ) : (
        <table className="w-full table-auto border-collapse">
          <thead>
            <tr className="bg-gray-100 text-left">
              <th className="px-4 py-2 text-sm text-gray-700">Title</th>
              <th className="px-4 py-2 text-sm text-gray-700">Created At</th>
              <th className="px-4 py-2 text-sm text-gray-700">Actions</th>
            </tr>
          </thead>
          <tbody>
            {blogs.map((blog) => (
              <tr key={blog.id} className="border-t">
                <td className="px-4 py-2">{blog.title}</td>
                <td className="px-4 py-2">{new Date(blog.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-2 flex gap-2">
                  <button
                    onClick={() => onEdit(blog)}
                    className="text-blue-500 hover:text-blue-700"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => onDelete(blog.id)}
                    className="text-red-500 hover:text-red-700"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default BlogList;
