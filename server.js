const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const methodOverride = require("method-override");
const mongoose = require("mongoose");
const multer = require("multer");
const details = require("./models/details");
const BlogPost = require("./models/blog"); // Ensure this model is correctly defined
const app = express();

// Dynamic port handling
const PORT = process.env.PORT || 5000;

// Database URI
const dbURI =
  "mongodb+srv://Jonathan:admin123@cluster.y7axs.mongodb.net/main-blog";

// Connect to MongoDB
mongoose
  .connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("Connected Successfully");
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch((err) => console.error("Database connection error:", err));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

// Configure session middleware
app.use(
  session({ secret: "secret-key", resave: false, saveUninitialized: true })
);

// Use method-override middleware
app.use(methodOverride("_method"));

// Configure body parsers
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Configure view engine
app.set("view engine", "ejs");

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "public/uploads")); // Ensure this directory exists
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext); // Unique filename
  },
});

const upload = multer({ storage: storage });

// Routes
app.get("/", (req, res) => {
  res.render("signin", { title: "Medium: Read and write stories" });
});

app.get("/signup", (req, res) => {
  res.render("signup", { title: "Medium: Read and write stories" });
});

app.get("/existing", (req, res) => {
  res.render("existing", { title: "Medium: Read and write stories" });
});

app.get("/success", (req, res) => {
  res.render("success", { title: "Medium: Read and write stories" });
});
app.get("/posted", (req, res) => {
  res.render("bs", { title: "Medium: Read and write stories" });
});
app.get("/err", (req, res) => {
  res.render("er", { title: "Medium: Read and write stories" });
});

app.get("/error", (req, res) => {
  res.render("error", { title: "Medium: Read and write stories" });
});

app.get("/view", (req, res) => {
  res.render("index-2", { title: "Medium: Read and write stories" });
});

app.get("/post", (req, res) => {
  res.render("index-5", { title: "Medium: Read and write stories" });
});
app.get("/home", (req, res) => {
  res.render("index", { title: "Medium: Read and write stories" });
});

// Sign-up Route
app.post("/signup", async (req, res) => {
  const { name, username, email, password, gender } = req.body;

  try {
    if (!email || !password) {
      return res.render("existing", {
        title: "Signup Error",
        message: "Email and password are required.",
      });
    }

    const existingUser = await details.findOne({ email });
    if (existingUser) {
      return res.render("existing", {
        title: "Signup Error",
        message: "Email already exists.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new details({
      name,
      username,
      email,
      password: hashedPassword,
      gender,
    });

    await newUser.save();

    res.render("success", {
      title: "Signup Success",
      message: "User registered successfully.",
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.render("error", {
      title: "Error",
      message: "An error occurred during sign-up. Please try again.",
    });
  }
});

// Sign-in Route
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await details.findOne({ email });
    if (!user) {
      return res.render("invalid", {
        title: "Sign-In Error",
        message: "Invalid email or password.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("invalid", {
        title: "Sign-In Error",
        message: "Invalid email or password.",
      });
    }

    req.session.userId = user._id;
    req.session.user = user;
    res.redirect("/blog");
  } catch (err) {
    console.error("Sign-in error:", err);
    res.render("error", {
      title: "Error",
      message: "An error occurred during sign-in. Please try again.",
    });
  }
});

// Dashboard Route
app.get("/dashboard", async (req, res) => {
  const userId = req.session.userId;

  try {
    const user = await details.findById(userId).lean();
    if (!user) {
      return res.status(404).render("error", {
        title: "User Not Found",
        message: "User data not found.",
      });
    }

    // Fetch the count of blog posts authored by the user
    const postCount = await BlogPost.countDocuments({ user: userId });

    res.render("index-3", {
      title: "Medium: Read and write stories",
      userName: user.name,
      userEmail: user.email,
      userUsername: user.username,
      userGender: user.gender,
      postCount, // Pass the post count to the view
    });
  } catch (err) {
    console.error("Error retrieving user data:", err);
    res.render("error", {
      title: "Error",
      message:
        "An error occurred while retrieving your data. Please try again.",
    });
  }
});

// Blog Route with Category and Search Filtering
app.get("/blog", async (req, res) => {
  try {
    const searchQuery = req.query.search || ""; // Get search query
    const selectedCategory = req.query.category || ""; // Get selected category

    let filter = {};

    // Add category filtering if a category is selected
    if (selectedCategory) {
      filter.type = selectedCategory;
    }

    // Add search filtering if a search query is present
    if (searchQuery) {
      filter.$or = [
        { title: { $regex: searchQuery, $options: "i" } },
        { body: { $regex: searchQuery, $options: "i" } },
        { snippet: { $regex: searchQuery, $options: "i" } },
      ];
    }

    // Fetch filtered blog posts based on the search query and category
    const blogs = await BlogPost.find(filter).lean();

    // Render the blog list page with the filtered blogs, search query, and category
    res.render("index", {
      title: "Blog",
      userName: req.session.user ? req.session.user.name : "Guest",
      blogs: blogs || [], // If no blogs, pass an empty array
      selectedCategory, // Pass selected category back to view
      searchQuery, // Pass search query back to view
    });
  } catch (err) {
    console.error("Error fetching blog posts:", err);
    res.render("error", {
      title: "Error",
      message: "An error occurred while fetching blog posts. Please try again.",
    });
  }
});

// Blog Post Route
app.post("/blog", upload.single("image"), async (req, res) => {
  try {
    const { title, snippet, body, type } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;

    console.log("Image path:", image); // Log the image path to debug

    if (!req.session.userId) {
      return res.render("error", {
        title: "Unauthorized",
        message: "You must be logged in to post a blog.",
      });
    }

    const newBlogPost = new BlogPost({
      title,
      snippet,
      body,
      type,
      image,
      user: req.session.userId,
      author: req.session.user.name,
    });

    await newBlogPost.save();

    // Render the success page
    res.render("bs", {
      title: "Blog Post Created",
      message: "Blog post created successfully!",
      redirectUrl: "/blog", // URL to redirect after showing the message (if needed)
    });
  } catch (err) {
    console.error("Error creating blog post:", err);

    // Render the error page
    res.render("er", {
      title: "Error",
      message:
        "An error occurred while creating the blog post. Please try again.",
      redirectUrl: "/blog", // URL to redirect after showing the message (if needed)
    });
  }
});

// Route to fetch and display a single blog post
app.get("/blog/:id", async (req, res) => {
  try {
    const blogId = req.params.id;
    const userId = req.session.userId; // Get the ID of the currently logged-in user

    if (!mongoose.Types.ObjectId.isValid(blogId)) {
      return res.status(400).render("error", {
        title: "Invalid Blog ID",
        message: "The provided blog ID is invalid.",
      });
    }

    const blogPost = await BlogPost.findById(blogId).lean();

    if (!blogPost) {
      return res.status(404).render("error", {
        title: "Blog Post Not Found",
        message: "The requested blog post does not exist.",
      });
    }

    // Pass the logged-in user's ID to the view
    res.render("index-2", {
      title: blogPost.title,
      blogPost,
      currentUserId: userId, // Add this line
    });
  } catch (err) {
    console.error("Error retrieving blog post:", err);
    res.status(500).render("error", {
      title: "Error",
      message: "An error occurred while retrieving the blog post.",
    });
  }
});

// Route to delete a blog post
app.delete("/blog/:id", async (req, res) => {
  try {
    const blogId = req.params.id;
    const userId = req.session.userId;

    // Ensure that the blogId is a valid MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(blogId)) {
      return res.status(400).render("error", {
        title: "Invalid Blog ID",
        message: "The provided blog ID is invalid.",
      });
    }

    // Find the blog post
    const blogPost = await BlogPost.findById(blogId);

    // Check if the post exists
    if (!blogPost) {
      return res.status(404).render("error", {
        title: "Blog Post Not Found",
        message: "The requested blog post does not exist.",
      });
    }

    // Check if the current user is the author of the post
    if (blogPost.user.toString() !== userId.toString()) {
      return res.status(403).render("error", {
        title: "Unauthorized",
        message: "You are not authorized to delete this post.",
      });
    }

    // Delete the post
    await BlogPost.findByIdAndDelete(blogId);

    // Redirect or render success message
    res.redirect("/blog");
  } catch (err) {
    console.error("Error deleting blog post:", err);
    res.status(500).render("error", {
      title: "Error",
      message: "An error occurred while deleting the blog post.",
    });
  }
});

// Logout Route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error during logout:", err);
      return res.redirect("/home"); // Redirect to the blog page on error
    }
    res.redirect("/"); // Redirect to the login page after successful logout
  });
});

// GET route to display the edit form
app.get("/blog/:id/edit", async (req, res) => {
  try {
    const blogPost = await BlogPost.findById(req.params.id).lean();

    if (!blogPost) {
      return res
        .status(404)
        .render("error", { message: "Blog post not found." });
    }

    // Ensure only the author can edit the post
    if (blogPost.user.toString() !== req.session.userId.toString()) {
      return res.status(403).render("error", {
        message: "You do not have permission to edit this post.",
      });
    }

    // Render the edit form
    res.render("index-4", {
      title: "Edit Blog Post",
      blogPost,
    });
  } catch (err) {
    console.error("Error fetching blog post:", err);
    res.render("error", { message: "An error occurred. Please try again." });
  }
});

// Middleware to ensure user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect("/login");
}

// PUT route to handle the blog post update
app.put(
  "/blog/:id",
  upload.single("image"),
  isAuthenticated,
  async (req, res) => {
    try {
      const { title, snippet, body } = req.body;
      const image = req.file ? `/uploads/${req.file.filename}` : null;

      // Find the blog post by its ID
      const blogPost = await BlogPost.findById(req.params.id);

      // If the blog post is not found, return a 404 error
      if (!blogPost) {
        return res
          .status(404)
          .render("error", { message: "Blog post not found." });
      }

      // Check if the user is the author of the post
      if (blogPost.user.toString() !== req.session.userId.toString()) {
        return res.status(403).render("error", {
          message: "You do not have permission to edit this post.",
        });
      }

      // Update the blog post
      blogPost.title = title;
      blogPost.snippet = snippet;
      blogPost.body = body;

      // If a new image is uploaded, update the image
      if (image) {
        blogPost.image = image;
      }

      await blogPost.save();

      // Redirect to home or previous page
      const redirectUrl = req.query.redirect || "/";
      res.redirect(redirectUrl);
    } catch (err) {
      console.error("Error updating blog post:", err);
      res.render("error", {
        message:
          "An error occurred while updating the blog post. Please try again.",
      });
    }
  }
);

// GET route for home page
app.get("/", (req, res) => {
  res.render("home", { user: req.session.userId });
});

app.get("/user", (req, res) => {
  if (req.session.userId) {
    // User is logged in, render home page with user-specific data
    res.render("home", { user: req.session.userId });
  } else {
    // User is not logged in, render home page without user-specific data
    res.render("home");
  }
});

module.exports = details;
