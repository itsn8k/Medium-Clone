require('dotenv').config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require('connect-mongo');
const methodOverride = require("method-override");
const mongoose = require("mongoose");
const multer = require("multer");
const details = require("./models/details");
const BlogPost = require("./models/blog"); // Ensure this model is correctly defined
const app = express();
const fs = require('fs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

// Dynamic port handling
const PORT = process.env.PORT || 5000;

// Database configuration
const username = encodeURIComponent(process.env.MONGODB_USERNAME);
const password = encodeURIComponent(process.env.MONGODB_PASSWORD);
const database = process.env.MONGODB_DATABASE;

// Construct the connection string
const dbURI = `mongodb+srv://${username}:${password}@cluster.y7axs.mongodb.net/${database}?retryWrites=true&w=majority`;

// Updated MongoDB connection configuration
mongoose.connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    retryWrites: true,
    w: 'majority',
    retryReads: true,
    connectTimeoutMS: 10000,
    maxPoolSize: 10,
    family: 4
})
.then(() => {
    console.log("Connected Successfully to MongoDB");
    console.log("Database Name:", mongoose.connection.name);
    console.log("Host:", mongoose.connection.host);
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
})
.catch((err) => {
    console.error("MongoDB connection error details:");
    console.error("Error name:", err.name);
    console.error("Error message:", err.message);
    console.error("Full error:", err);
    process.exit(1);
});

// Add reconnection handling
mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected! Attempting to reconnect...');
    setTimeout(() => {
        mongoose.connect(dbURI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000
        }).catch(err => {
            console.error('Reconnection failed:', err);
        });
    }, 5000); // Wait 5 seconds before trying to reconnect
});

// Add connection error handler
mongoose.connection.on('error', err => {
    console.error('MongoDB connection error:', err);
});

// Handle process termination
process.on('SIGINT', async () => {
    try {
        await mongoose.connection.close();
        console.log('MongoDB connection closed through app termination');
        process.exit(0);
    } catch (err) {
        console.error('Error closing MongoDB connection:', err);
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
    secret: process.env.SESSION_SECRET || "secret-key",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: dbURI,
      ttl: 14 * 24 * 60 * 60, // = 14 days. Default
      autoRemove: 'native', // Default
      crypto: {
        secret: process.env.SESSION_SECRET || "secret-key",
      },
      touchAfter: 24 * 3600 // time period in seconds
    }),
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days
      sameSite: 'lax'
    }
  })
);

// Add error handling for the session store
app.use((req, res, next) => {
  if (!req.session) {
    return next(new Error('Session store unavailable'));
  }
  next();
});

// Use method-override middleware
app.use(methodOverride("_method"));

// Configure body parsers
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Configure view engine
app.set("view engine", "ejs");

// Add this before configuring multer
const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Add file type validation
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Invalid file type'), false);
        }
        const ext = path.extname(file.originalname);
        cb(null, `${Date.now()}${ext}`);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Add this after your multer configuration
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        // A Multer error occurred when uploading
        console.error("Multer error:", err);
        return res.render("er", {
            title: "Upload Error",
            message: "An error occurred while uploading the image. Please try again.",
            redirectUrl: "/blog"
        });
    } else if (err) {
        // An unknown error occurred
        console.error("Unknown error:", err);
        return res.render("er", {
            title: "Error",
            message: "An unexpected error occurred. Please try again.",
            redirectUrl: "/blog"
        });
    }
    next();
});

// Move this section up, before any routes that use requireAuth
// Add authentication middleware for protected routes
const requireAuth = async (req, res, next) => {
  try {
    // Check if user is authenticated via session
    if (req.session.userId) {
      return next();
    }

    // Check if user has a valid remember token
    if (req.cookies.remember_token) {
      const user = await details.findOne({
        rememberToken: req.cookies.remember_token
      });

      if (user) {
        // Set up the session
        req.session.userId = user._id;
        req.session.user = user;
        return next();
      }
    }

    // If no valid session or remember token, redirect to signin
    res.redirect('/?error=Please sign in to continue');
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.redirect('/?error=Authentication error');
  }
};

// Add CSRF protection middleware
app.use((req, res, next) => {
  res.locals.isAuthenticated = !!req.session.userId;
  res.locals.currentUser = req.session.user;
  next();
});

// Authentication Routes - Place these after your middleware configurations but before other routes

// GET Routes for Authentication
app.get("/", (req, res) => {
  if (req.session.userId) {
    res.redirect("/dashboard");
  } else {
    res.render("signin", { 
      title: "Medium: Read and write stories",
      error: req.query.error 
    });
  }
});

app.get("/signin", (req, res) => {
  if (req.session.userId) {
    res.redirect("/dashboard");
  } else {
    res.render("signin", { title: "Sign In" });
  }
});

app.get("/signup", (req, res) => {
  if (req.session.userId) {
    res.redirect("/dashboard");
  } else {
    res.render("signup", { title: "Sign Up" });
  }
});

// POST Routes for Authentication
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await details.findOne({ email });
    
    if (!user) {
      return res.render("signin", {
        error: "Invalid email or password",
        values: { email }
      });
    }

    // Compare password
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.render("signin", {
        error: "Invalid email or password",
        values: { email }
      });
    }

    // Set session
    req.session.userId = user._id;
    req.session.user = user;

    // Handle remember me
    if (req.body.remember_me) {
      const token = crypto.randomBytes(32).toString('hex');
      user.rememberToken = token;
      await user.save();
      res.cookie('remember_token', token, { 
        maxAge: 30 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
      });
    }

    res.redirect("/dashboard");

  } catch (err) {
    console.error("Login error:", err);
    res.render("signin", {
      error: "Login failed. Please try again.",
      values: { email: req.body.email }
    });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { username, name, email, password, gender } = req.body;

    // Check existing user
    const existingUser = await details.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.render("signup", {
        error: "Email or username already exists",
        values: { username, name, email, gender }
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new details({
      username,
      name,
      email,
      password: hashedPassword,
      gender
    });

    await user.save();

    // Set session
    req.session.userId = user._id;
    req.session.user = user;
    res.redirect("/dashboard");

  } catch (err) {
    console.error("Registration error:", err);
    res.render("signup", {
      error: "Registration failed. Please try again.",
      values: req.body
    });
  }
});

// Routes
app.get("/", async (req, res) => {
  try {
    // Check if user is already authenticated via session
    if (req.session.userId) {
      return res.redirect("/blog");
    }

    // Check if user has a valid remember token
    if (req.cookies.remember_token) {
      const user = await details.findOne({
        rememberToken: req.cookies.remember_token
      });

      if (user) {
        // Set up the session
        req.session.userId = user._id;
        req.session.user = user;
        return res.redirect("/blog");
      }
    }

    // If no valid session or remember token, show signin page
    res.render("signin", { 
      title: "Medium: Read and write stories",
      error: req.query.error 
    });
  } catch (err) {
    console.error("Authentication check error:", err);
    res.render("signin", { 
      title: "Medium: Read and write stories",
      error: "An error occurred. Please try again." 
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

app.get("/post", requireAuth, async (req, res) => {
  res.render("index-5", { title: "Medium: Read and write stories" });
});
app.get("/home", (req, res) => {
  res.render("index", { title: "Medium: Read and write stories" });
});

// Dashboard Route
app.get("/dashboard", requireAuth, async (req, res) => {
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

    // Calculate total views from all user's posts
    const userPosts = await BlogPost.find({ user: userId });
    const totalViews = userPosts.reduce((sum, post) => sum + (post.views || 0), 0);

    res.render("index-3", {
      title: "Medium: Read and write stories",
      userName: user.name,
      userEmail: user.email,
      userUsername: user.username,
      userGender: user.gender,
      postCount,
      totalViews // Pass total views to the template
    });
  } catch (err) {
    console.error("Error retrieving user data:", err);
    res.render("error", {
      title: "Error",
      message: "An error occurred while retrieving your data. Please try again.",
    });
  }
});

// Blog Route with Category and Search Filtering
app.get("/blog", requireAuth, async (req, res) => {
  try {
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
    const blogs = await BlogPost.find(filter)
      .sort({ createdAt: -1 })
      .lean();

    // Group blogs by date
    const groupedBlogs = blogs.reduce((groups, blog) => {
      const date = new Date(blog.createdAt);
      const today = new Date();
      const yesterday = new Date(today);
      yesterday.setDate(yesterday.getDate() - 1);

      let dateString;
      if (date.toDateString() === today.toDateString()) {
        dateString = 'Today';
      } else if (date.toDateString() === yesterday.toDateString()) {
        dateString = 'Yesterday';
      } else {
        dateString = date.toLocaleDateString('en-US', { 
          weekday: 'long',
          month: 'long', 
          day: 'numeric'
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
      updateMessage: req.session.updateMessage
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
        let imagePath = null;

        if (req.file) {
            // Store the path relative to the public directory
            imagePath = `/uploads/${req.file.filename}`;
            console.log("Uploaded image path:", imagePath);
        }

        if (!req.session.userId) {
            return res.render("error", {
                title: "Unauthorized",
                message: "You must be logged in to post a blog."
            });
        }

        const newBlogPost = new BlogPost({
            title,
            snippet,
            body,
            type,
            image: imagePath, // Use the relative path
            user: req.session.userId,
            author: req.session.user.name
        });

        await newBlogPost.save();
        res.render("bs", {
            title: "Blog Post Created",
            message: "Blog post created successfully!",
            redirectUrl: "/blog"
        });
    } catch (err) {
        console.error("Error creating blog post:", err);
        res.render("er", {
            title: "Error",
            message: "An error occurred while creating the blog post. Please try again.",
            redirectUrl: "/blog"
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
app.get("/logout", async (req, res) => {
  try {
    if (req.session.userId) {
      // Clear the remember token in the database
      await details.findByIdAndUpdate(req.session.userId, {
        rememberToken: null
      });
    }
    
    // Clear the cookie
    res.clearCookie('remember_token');
    
    // Destroy the session
    req.session.destroy((err) => {
      if (err) {
        console.error("Error during logout:", err);
      }
      res.redirect("/");
    });
  } catch (err) {
    console.error("Logout error:", err);
    res.redirect("/");
  }
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
    const { title, snippet, body } = req.body;
    const blogId = req.params.id;

    // Validate blogId
    if (!mongoose.Types.ObjectId.isValid(blogId)) {
      return res.status(400).render("error", {
        title: "Invalid Blog ID",
        message: "The provided blog ID is invalid."
      });
    }

    // Find the blog post
    const blogPost = await BlogPost.findById(blogId);

    // Check if post exists
    if (!blogPost) {
      return res.status(404).render("error", {
        title: "Not Found",
        message: "Blog post not found."
      });
    }

    // Verify ownership
    if (blogPost.user.toString() !== req.session.userId.toString()) {
      return res.status(403).render("error", {
        title: "Unauthorized",
        message: "You do not have permission to edit this post."
      });
    }

    // Prepare update data
    const updateData = {
      title,
      snippet,
      body
    };

    // Handle image upload if provided
    if (req.file) {
      updateData.image = `/uploads/${req.file.filename}`;
      
      // Delete old image if it exists
      if (blogPost.image) {
        const oldImagePath = path.join(__dirname, 'public', blogPost.image);
        try {
          if (fs.existsSync(oldImagePath)) {
            fs.unlinkSync(oldImagePath);
          }
        } catch (err) {
          console.error('Error deleting old image:', err);
        }
      }
    }

    // Update the blog post
    const updatedPost = await BlogPost.findByIdAndUpdate(
      blogId,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedPost) {
      throw new Error('Failed to update blog post');
    }

    // Show success message and redirect to main page
    req.session.updateMessage = "Blog post updated successfully!";
    res.redirect("/blog"); // Redirect to main page instead of individual post
  } catch (err) {
    console.error('Error updating blog post:', err);
    res.render("error", {
      title: "Error",
      message: "An error occurred while updating the blog post."
    });
  }
});

// Route to handle post likes
app.post('/blog/:id/like', requireAuth, async (req, res) => {
  try {
    const blogId = req.params.id;
    const userId = req.session.userId;

    const blog = await BlogPost.findById(blogId);
    if (!blog) {
      return res.status(404).json({ error: 'Blog post not found' });
    }

    // Initialize likes array if it doesn't exist
    if (!blog.likes) {
      blog.likes = [];
    }

    // Check if user already liked the post
    const userLikeIndex = blog.likes.indexOf(userId);
    if (userLikeIndex === -1) {
      // User hasn't liked the post, add like
      blog.likes.push(userId);
    } else {
      // User already liked the post, remove like
      blog.likes.splice(userLikeIndex, 1);
    }

    await blog.save();
    res.json({ likes: blog.likes.length, isLiked: userLikeIndex === -1 });
  } catch (err) {
    console.error('Error handling like:', err);
    res.status(500).json({ error: 'Failed to update like' });
  }
});

// Route to increment view count
app.post('/blog/:id/view', async (req, res) => {
  try {
    const blogId = req.params.id;
    const blog = await BlogPost.findById(blogId);
    
    if (!blog) {
      return res.status(404).json({ error: 'Blog post not found' });
    }

    // Initialize views if it doesn't exist
    if (!blog.views) {
      blog.views = 0;
    }

    blog.views += 1;
    await blog.save();
    
    res.json({ views: blog.views });
  } catch (err) {
    console.error('Error updating view count:', err);
    res.status(500).json({ error: 'Failed to update view count' });
  }
});

module.exports = details;
