require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const methodOverride = require("method-override");
const mongoose = require("mongoose");
const multer = require("multer");
const details = require("./models/details");
const BlogPost = require("./models/blog"); // Ensure this model is correctly defined
const app = express();
const fs = require("fs");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

// Dynamic port handling
const PORT = process.env.PORT || 5000;

// MongoDB Connection
const mongoURI = process.env.MONGODB_URI;

mongoose
  .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverApi: {
      version: "1",
      strict: true,
      deprecationErrors: true,
    },
  })
  .then(() => {
    console.log("MongoDB Connected Successfully");
    // Initialize Express app after successful connection
    initializeApp();
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// MongoDB Connection Events
mongoose.connection.on("error", (err) => {
  console.error("MongoDB connection error:", err);
});

mongoose.connection.on("disconnected", () => {
  console.log("MongoDB disconnected");
});

// Function to initialize Express app
function initializeApp() {
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(methodOverride("_method"));

  // Configure session middleware
  app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        mongoUrl: mongoURI,
        collectionName: "sessions",
      }),
      cookie: {
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
      },
    })
  );

  // Set up view engine and static files
  app.set("view engine", "ejs");
  app.use(express.static(path.join(__dirname, "public")));
  app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

  // Add user data to locals
  app.use((req, res, next) => {
    res.locals.user = req.session.user;
    next();
  });

  // Start the server
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

// Handle MongoDB connection events
mongoose.connection.on("connected", () => {
  console.log("Mongoose connected to MongoDB");
});

mongoose.connection.on("error", (err) => {
  console.error("Mongoose connection error:", err);
});

mongoose.connection.on("disconnected", () => {
  console.log("Mongoose disconnected");
});

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("SIGTERM received");
  try {
    await mongoose.connection.close();
    console.log("Mongoose connection closed through app termination");
    process.exit(0);
  } catch (err) {
    console.error("Error closing Mongoose connection:", err);
    process.exit(1);
  }
});

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

// Configure session middleware
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: mongoURI,
      collectionName: "sessions",
      stringify: false,
      autoRemove: "interval",
      autoRemoveInterval: 24 * 60, // 1 day in minutes
    }),
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

// Add this right after session configuration
app.use((req, res, next) => {
  if (!req.session) {
    return next(new Error("Session initialization failed"));
  }
  next();
});

// Make sure this is before any routes
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

// Use method-override middleware
app.use(methodOverride("_method"));

// Configure body parsers
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Configure view engine
app.set("view engine", "ejs");

// Update the upload directory structure
const uploadDir = "public/uploads";

// Create upload directory if it doesn't exist
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log(`Created directory: ${uploadDir}`);
}

// Make uploads directory publicly accessible
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

// Update multer configuration for blog post images only
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // Create a clean filename with timestamp and random string
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const fileExtension = path.extname(file.originalname).toLowerCase();
    cb(null, `post-${uniqueSuffix}${fileExtension}`);
  },
});

// Improve file filter for better security
const fileFilter = (req, file, cb) => {
  // Allow only specific image types
  const allowedTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new Error(
        "Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed."
      ),
      false
    );
  }
};

// Configure multer with improved settings
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1, // Allow only 1 file per upload
  },
});

// Add this after your multer configuration
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    // A Multer error occurred when uploading
    console.error("Multer error:", err);
    return res.render("er", {
      title: "Upload Error",
      message: "An error occurred while uploading the image. Please try again.",
      redirectUrl: "/blog",
    });
  } else if (err) {
    // An unknown error occurred
    console.error("Unknown error:", err);
    return res.render("er", {
      title: "Error",
      message: "An unexpected error occurred. Please try again.",
      redirectUrl: "/blog",
    });
  }
  next();
});

// Add middleware definitions at the top of server.js, after your imports but before routes
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect("/signin");
  }
  next();
};

// Add this middleware to check user authentication
const checkAuth = (req, res, next) => {
  if (req.session.userId || req.query.guest) {
    next();
  } else {
    res.redirect("/signin");
  }
};

// Add this middleware to check full user privileges
const checkFullAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.render("signin", {
      error: "Please sign in to access this feature",
      isGuest: req.query.guest,
    });
  }
};

// Add guest-check to the header navigation
app.use((req, res, next) => {
  res.locals.isGuest = req.query.guest === "true";
  res.locals.isAuthenticated = !!req.session.userId;
  next();
});

// Authentication Routes
app.get("/signin", (req, res) => {
  if (req.session.userId) {
    res.redirect("/blog");
  } else {
    res.render("signin", {
      title: "Sign In",
      error: null,
      values: {},
    });
  }
});

app.get("/signup", (req, res) => {
  if (req.session.userId) {
    res.redirect("/blog");
  } else {
    res.render("signup", {
      title: "Sign Up",
      error: null,
      values: {},
    });
  }
});

// Signup Route
app.post("/signup", upload.single("image"), async (req, res) => {
  try {
    const { name, email, username, password, gender } = req.body;

    // Check if user exists
    const existingUser = await details.findOne({
      $or: [{ email: email.toLowerCase() }, { username }],
    });

    if (existingUser) {
      return res.render("signup", {
        error: "Email or username already exists",
        values: req.body,
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Set default image if none provided
    const userImage = req.file
      ? `/uploads/${req.file.filename}`
      : "https://miro.medium.com/v2/resize:fit:1400/1*psYl0y9DUzZWtHzFJLIvTw.png";

    // Create new user
    const user = new details({
      name,
      email: email.toLowerCase(),
      username,
      password: hashedPassword,
      gender,
      image: userImage,
    });

    await user.save();

    // Set session
    req.session.userId = user._id;
    req.session.user = {
      name: user.name,
      username: user.username,
      email: user.email,
      image: user.image,
    };

    res.redirect("/blog");
  } catch (err) {
    console.error("Signup error:", err);
    res.render("signup", {
      error: "Signup failed. Please try again.",
      values: req.body,
    });
  }
});

// Login route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await details.findOne({ email: email.toLowerCase() });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render("signin", {
        error: "Invalid email or password",
        values: { email },
      });
    }

    // Set session
    req.session.userId = user._id;
    req.session.user = {
      name: user.name,
      username: user.username,
      email: user.email,
      image: user.image,
    };

    res.redirect("/blog");
  } catch (err) {
    console.error("Login error:", err);
    res.render("signin", {
      error: "Login failed. Please try again.",
      values: { email },
    });
  }
});

// Routes
app.get("/", async (req, res) => {
  if (req.session.userId) {
    res.redirect("/blog");
  } else {
    res.render("signin", {
      title: "Sign In - Medium",
    });
  }
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

app.get("/post", isAuthenticated, (req, res) => {
  res.render("index-5", {
    title: "Create New Story - Medium",
    user: req.session.user,
  });
});

app.get("/home", (req, res) => {
  res.render("index", { title: "Medium: Read and write stories" });
});

// Dashboard Route
app.get("/dashboard", isAuthenticated, async (req, res) => {
  try {
    // Get user's posts with views and likes
    const userPosts = await BlogPost.find({
      user: req.session.userId,
    }).sort({ createdAt: -1 });

    // Calculate total stats
    const stats = {
      totalPosts: userPosts.length,
      totalViews: userPosts.reduce((sum, post) => sum + (post.views || 0), 0),
      totalLikes: userPosts.reduce(
        (sum, post) => sum + (post.likes?.length || 0),
        0
      ),
      recentPosts: userPosts.slice(0, 5).map((post) => ({
        title: post.title,
        views: post.views || 0,
        likes: post.likes?.length || 0,
        createdAt: post.createdAt,
      })),
    };

    res.render("index-3", {
      user: req.session.user,
      stats: stats,
      recentPosts: stats.recentPosts,
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.render("error", {
      message: "Error loading dashboard",
    });
  }
});

// Image upload route
app.post(
  "/upload-image",
  isAuthenticated,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No image provided" });
      }

      const imageUrl = `/uploads/${req.file.filename}`;

      // Save image reference to user's images collection
      await saveUserImage(req.session.userId, imageUrl, req.file.originalname);

      res.json({
        success: true,
        imageUrl: imageUrl,
        message: "Image uploaded successfully",
      });
    } catch (err) {
      console.error("Image upload error:", err);
      res.status(500).json({ error: "Failed to upload image" });
    }
  }
);

// Helper function to get user's images
async function getUserImages(userId) {
  try {
    const user = await details.findById(userId);
    return user.uploadedImages || [];
  } catch (err) {
    console.error("Error getting user images:", err);
    return [];
  }
}

// Helper function to save image reference
async function saveUserImage(userId, imageUrl, originalName) {
  try {
    await details.findByIdAndUpdate(userId, {
      $push: {
        uploadedImages: {
          url: imageUrl,
          name: originalName,
          uploadedAt: new Date(),
        },
      },
    });
  } catch (err) {
    console.error("Error saving image reference:", err);
    throw err;
  }
}

// Blog Route with Category and Search Filtering
app.get("/blog", checkAuth, async (req, res) => {
  try {
    const isGuest = req.query.guest === "true";
    const searchQuery = req.query.search || "";
    const selectedCategory = req.query.category || "";

    let filter = {};

    if (selectedCategory) {
      filter.type = selectedCategory;
    }

    if (searchQuery) {
      filter.$or = [
        { title: { $regex: searchQuery, $options: "i" } },
        { body: { $regex: searchQuery, $options: "i" } },
        { snippet: { $regex: searchQuery, $options: "i" } },
      ];
    }

    // Fetch blogs and sort by createdAt in descending order
    const blogs = await BlogPost.find(filter).sort({ createdAt: -1 }).lean();

    // Group blogs by date
    const groupedBlogs = blogs.reduce((groups, blog) => {
      const date = new Date(blog.createdAt);
      const today = new Date();
      const yesterday = new Date(today);
      yesterday.setDate(yesterday.getDate() - 1);

      let dateString;
      if (date.toDateString() === today.toDateString()) {
        dateString = "Today";
      } else if (date.toDateString() === yesterday.toDateString()) {
        dateString = "Yesterday";
      } else {
        dateString = date.toLocaleDateString("en-US", {
          weekday: "long",
          month: "long",
          day: "numeric",
        });
      }

      if (!groups[dateString]) {
        groups[dateString] = [];
      }
      groups[dateString].push(blog);
      return groups;
    }, {});

    res.render("index", {
      title: "Blog",
      userName: req.session.user ? req.session.user.name : "Guest",
      groupedBlogs,
      selectedCategory,
      searchQuery,
      updateMessage: req.session.updateMessage,
      isGuest: isGuest,
    });

    // Clear update message after rendering
    delete req.session.updateMessage;
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

    // Check for required image
    if (!req.file) {
      return res.render("er", {
        title: "Error",
        message: "Please upload an image for your blog post.",
        redirectUrl: "/post",
      });
    }

    // Set the correct image path
    const imagePath = `/uploads/${req.file.filename}`;
    console.log("Uploaded image path:", imagePath);

    if (!req.session.userId) {
      return res.render("error", {
        title: "Unauthorized",
        message: "You must be logged in to post a blog.",
      });
    }

    // Create and save the blog post
    const newBlogPost = new BlogPost({
      title,
      snippet,
      body,
      type,
      image: imagePath,
      user: req.session.userId,
      author: req.session.user.name,
      createdAt: new Date(),
      views: 0,
      likes: [],
      comments: [],
    });

    await newBlogPost.save();
    res.render("bs", {
      title: "Blog Post Created",
      message: "Blog post created successfully!",
      redirectUrl: "/blog",
    });
  } catch (err) {
    console.error("Error creating blog post:", err);
    res.render("er", {
      title: "Error",
      message:
        "An error occurred while creating the blog post. Please try again.",
      redirectUrl: "/post",
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
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
    }
    res.redirect("/signin");
  });
});

// GET route to display the edit form
app.get("/blog/:id/edit", isAuthenticated, async (req, res) => {
  try {
    const blogPost = await BlogPost.findById(req.params.id);
    if (!blogPost) {
      return res.status(404).redirect("/blog");
    }

    // Check if user is the author by comparing user IDs instead of username
    if (blogPost.user.toString() !== req.session.userId.toString()) {
      return res.status(403).redirect("/blog");
    }

    res.render("index-4", {
      title: "Edit Story | Medium",
      blogPost,
      user: req.session.user,
    });
  } catch (err) {
    console.error("Error loading edit page:", err);
    res.redirect("/blog");
  }
});

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

// PUT route to handle blog post updates
app.put("/blog/:id", upload.single("image"), requireAuth, async (req, res) => {
  try {
    const { title, snippet, body, type } = req.body;
    const blogId = req.params.id;

    // Find the blog post
    const blogPost = await BlogPost.findById(blogId);
    if (!blogPost) {
      return res.status(404).render("error", {
        title: "Not Found",
        message: "Blog post not found.",
      });
    }

    // Verify ownership
    if (blogPost.user.toString() !== req.session.userId.toString()) {
      return res.status(403).render("error", {
        title: "Unauthorized",
        message: "You do not have permission to edit this post.",
      });
    }

    // Prepare update data
    const updateData = {
      title,
      snippet,
      body,
      type,
    };

    // Handle image upload if provided
    if (req.file) {
      updateData.image = `/uploads/${req.file.filename}`;

      // Delete old image if it exists
      if (blogPost.image) {
        const oldImagePath = path.join(__dirname, "public", blogPost.image);
        try {
          if (fs.existsSync(oldImagePath)) {
            fs.unlinkSync(oldImagePath);
          }
        } catch (err) {
          console.error("Error deleting old image:", err);
        }
      }
    }

    const updatedPost = await BlogPost.findByIdAndUpdate(blogId, updateData, {
      new: true,
      runValidators: true,
    });

    res.redirect(`/blog/${blogId}`);
  } catch (err) {
    console.error("Error updating blog post:", err);
    res.render("error", {
      title: "Error",
      message: "An error occurred while updating the blog post.",
    });
  }
});

// Route to handle post likes
app.post("/blog/:id/like", checkFullAuth, async (req, res) => {
  try {
    const blogId = req.params.id;
    const userId = req.session.userId;
    const userName = req.session.user.name;

    const blog = await BlogPost.findById(blogId);
    if (!blog) {
      return res.status(404).json({ error: "Blog post not found" });
    }

    const userLikeIndex = blog.likes.indexOf(userId);
    if (userLikeIndex === -1) {
      blog.likes.push(userId);
    } else {
      blog.likes.splice(userLikeIndex, 1);
    }

    await blog.save();

    res.json({
      likes: blog.likes.length,
      isLiked: userLikeIndex === -1,
      notification: {
        type: "like",
        postTitle: blog.title,
        userName: userName,
      },
    });
  } catch (err) {
    console.error("Error handling like:", err);
    res.status(500).json({ error: "Failed to update like" });
  }
});

// Route to increment view count
app.post("/blog/:id/view", async (req, res) => {
  try {
    const blogId = req.params.id;
    const blog = await BlogPost.findById(blogId);

    if (!blog) {
      return res.status(404).json({ error: "Blog post not found" });
    }

    // Initialize views if it doesn't exist
    if (!blog.views) {
      blog.views = 0;
    }

    blog.views += 1;
    await blog.save();

    // Emit notification to the post author (you'll need to implement WebSocket here)
    // For now, we'll just send it in the response
    res.json({
      views: blog.views,
      notification: {
        type: "view",
        postId: blogId,
        title: blog.title,
      },
    });
  } catch (err) {
    console.error("Error updating view count:", err);
    res.status(500).json({ error: "Failed to update view count" });
  }
});

// Remember token authentication route
app.get("/auth/remember", async (req, res) => {
  try {
    if (req.cookies.remember_token) {
      const user = await details.findOne({
        rememberToken: req.cookies.remember_token,
      });

      if (user) {
        req.session.userId = user._id;
        req.session.user = {
          name: user.name,
          username: user.username,
          email: user.email,
        };
        return res.redirect("/blog"); // Changed from /dashboard to /blog
      }
    }
    res.redirect("/signin");
  } catch (err) {
    console.error("Remember token auth error:", err);
    res.redirect("/signin");
  }
});

// Add this after your routes
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).render("signup", {
        error: "File is too large. Maximum size is 5MB",
        values: req.body,
      });
    }
  }
  next(error);
});

// Configure multer for profile images
const profileStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const profileUploadDir = "public/uploads/profiles";
    // Create directory if it doesn't exist
    if (!fs.existsSync(profileUploadDir)) {
      fs.mkdirSync(profileUploadDir, { recursive: true });
    }
    cb(null, profileUploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const fileExtension = path.extname(file.originalname).toLowerCase();
    cb(null, `profile-${uniqueSuffix}${fileExtension}`);
  },
});

const profileUpload = multer({
  storage: profileStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          "Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed."
        )
      );
    }
  },
});

// Profile image update route
app.post(
  "/update-profile-image",
  isAuthenticated,
  profileUpload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: "No image provided",
        });
      }

      const imageUrl = `/uploads/profiles/${req.file.filename}`;

      // Update user in database
      const updatedUser = await details.findByIdAndUpdate(
        req.session.userId,
        { image: imageUrl },
        { new: true }
      );

      if (!updatedUser) {
        return res.status(404).json({
          success: false,
          error: "User not found",
        });
      }

      // Update session
      req.session.user = {
        ...req.session.user,
        image: imageUrl,
      };

      res.json({
        success: true,
        imageUrl: imageUrl,
      });
    } catch (err) {
      console.error("Profile image update error:", err);
      res.status(500).json({
        success: false,
        error: "Failed to update profile image",
      });
    }
  }
);

// Update the isAuthenticated middleware to include user data
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    // Make sure user data is available in session
    if (!req.session.user) {
      // If user data is missing, fetch it from database
      details
        .findById(req.session.userId)
        .then((user) => {
          if (user) {
            req.session.user = {
              name: user.name,
              username: user.username,
              email: user.email,
              image: user.image,
            };
            next();
          } else {
            res.redirect("/signin");
          }
        })
        .catch((err) => {
          console.error("Auth middleware error:", err);
          res.redirect("/signin");
        });
    } else {
      next();
    }
  } else {
    res.redirect("/signin");
  }
}

// Add this route for handling blog post creation with image
app.post("/create-post", upload.single("image"), async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const { title, content, description } = req.body;
    let imageUrl = null;

    // Handle image upload if present
    if (req.file) {
      imageUrl = `/uploads/blogs/${req.file.filename}`;
    }

    // Create new blog post
    const newPost = new BlogPost({
      title,
      content,
      description,
      image: imageUrl,
      author: req.session.user.username,
      user: req.session.userId,
      createdAt: new Date(),
      views: 0,
      likes: [],
      comments: [],
    });

    await newPost.save();

    res.json({
      success: true,
      post: newPost,
      message: "Post created successfully",
    });
  } catch (err) {
    console.error("Error creating post:", err);
    res.status(500).json({
      success: false,
      error: "Failed to create post",
    });
  }
});

// Add route for getting blog post creation page
app.get("/post", isAuthenticated, (req, res) => {
  res.render("index-5", {
    title: "Create New Story - Medium",
    user: req.session.user,
  });
});

// Add route for blog post preview
app.get("/preview", isAuthenticated, (req, res) => {
  res.render("index-5", {
    title: "Preview Story - Medium",
    user: req.session.user,
  });
});

module.exports = details;
