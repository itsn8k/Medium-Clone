const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const detailsSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      match: [/.+@.+\..+/, "Please enter a valid email address"], // Validation for email format
    },
    password: {
      type: String,
      required: true,
    },
    gender: {
      type: String,
      enum: ["male", "female", "other"], // Restrict to specific values
      required: true,
    },
  },
  { timestamps: true }
);

const details = mongoose.model("blog-details", detailsSchema);
module.exports = details;
