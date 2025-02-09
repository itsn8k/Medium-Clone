const mongoose = require("mongoose");

// Define BlogPost Schema
const blogSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  snippet: {
    type: String,
    required: true,
    trim: true,
  },
  body: {
    type: String,
    required: true,
    trim: true,
  },
  image: {
    type: String, // Store the filename or path to the uploaded image
    required: false,
  },
  type: {
    type: String,
    required: true,
    trim: true,
  },
  user: {
    type: mongoose.Schema.Types.ObjectId, // Reference to the User model
    ref: "User",
    required: true,
  },
  author: {
    type: String,
    required: true,
    trim: true,
  },
  views: {
    type: Number,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Create BlogPost model
const BlogPost = mongoose.model("blog-post", blogSchema);

module.exports = BlogPost;
