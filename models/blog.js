const mongoose = require("mongoose");

// Define BlogPost Schema
const blogSchema = new mongoose.Schema(
  {
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
      type: String,
      required: true, // Make image required
    },
    type: {
      type: String,
      required: true,
      enum: [
        "Tech & Gadgets",
        "Fashion & Beauty",
        "News",
        "Food & Recipes",
        "Lifestyle",
        "Programming",
        "Data Science",
      ],
      trim: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "blog-details", // Update this to match your user model name
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
    likes: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "blog-details",
      },
    ],
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

// Create BlogPost model
const BlogPost = mongoose.model("blog-post", blogSchema);

module.exports = BlogPost;
