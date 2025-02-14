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

// Update MongoDB connection configuration
const username = encodeURIComponent(process.env.MONGODB_USERNAME);
const password = encodeURIComponent(process.env.MONGODB_PASSWORD);
const database = process.env.MONGODB_DATABASE;
const cluster = 'cluster.y7axs'; // Your cluster name

const mongoURI = `mongodb+srv://${username}:${password}@${cluster}.mongodb.net/${database}?retryWrites=true&w=majority`;

// Enhanced MongoDB connection options
const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  family: 4,  // Force IPv4
  retryWrites: true,
  // Add these for Atlas
  ssl: true,
  authSource: 'admin',
  replicaSet: 'atlas-yeqx7i-shard-0'
};

// Connect with retry mechanism
const connectWithRetry = () => {
  console.log('MongoDB connection with retry');
  mongoose.connect(mongoURI, mongooseOptions)
    .then(() => {
      console.log('MongoDB is connected');
      console.log('Database Name:', mongoose.connection.name);
      console.log('Host:', mongoose.connection.host);
      app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
      });
    })
    .catch(err => {
      console.error('MongoDB connection unsuccessful, retry after 5 seconds.');
      console.error(err);
      setTimeout(connectWithRetry, 5000);
    });
};

// Initial connection
connectWithRetry();

// Connection event handlers
mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected');
});

// Graceful shutdown
process.on('SIGINT', async () => {
  try {
    await mongoose.connection.close();
    console.log('Mongoose connection closed through app termination');
    process.exit(0);
  } catch (err) {
    console.error('Error closing Mongoose connection:', err);
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
      mongoUrl: mongoURI,
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

// Create upload directories if they don't exist
const uploadDirs = [
  'public/uploads',
  'public/uploads/profiles',
  'public/uploads/blogs',
  'public/uploads/others'
];

uploadDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`Created directory: ${dir}`);
  }
});

// Make sure uploads directory is publicly accessible
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// Update multer configuration for all file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Check file type to determine destination
    if (file.fieldname === 'image') {
      cb(null, 'public/uploads/profiles');
    } else if (file.fieldname === 'blogImage') {
      cb(null, 'public/uploads/blogs');
    } else {
      cb(null, 'public/uploads/others');
    }
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// Multer file filter
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Not an image! Please upload an image.'), false);
  }
};

// Configure multer with storage and file filter
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
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

// Add middleware definitions at the top of server.js, after your imports but before routes
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/signin');
  }
  next();
};

// Add this middleware to check user authentication
const checkAuth = (req, res, next) => {
  if (req.session.userId || req.query.guest) {
    next();
  } else {
    res.redirect('/signin');
  }
};

// Add this middleware to check full user privileges
const checkFullAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.render('signin', {
      error: 'Please sign in to access this feature',
      isGuest: req.query.guest
    });
  }
};

// Add guest-check to the header navigation
app.use((req, res, next) => {
  res.locals.isGuest = req.query.guest === 'true';
  res.locals.isAuthenticated = !!req.session.userId;
  next();
});

// Authentication Routes - Place these after your middleware configurations but before other routes

// GET Routes for Authentication
app.get("/", async (req, res) => {
  try {
    if (req.session.userId) {
      res.redirect('/blog');
    } else {
      // Fetch top 3 trending posts based on views and likes
      const trendingPosts = await BlogPost.aggregate([
        {
          $addFields: {
            trendingScore: {
              $add: [
                { $ifNull: ["$views", 0] },
                { $size: { $ifNull: ["$likes", []] } }
              ]
            }
          }
        },
        { $sort: { trendingScore: -1 } },
        { $limit: 3 },
        {
          $lookup: {
            from: "details",
            localField: "author",
            foreignField: "username",
            as: "authorDetails"
          }
        },
        {
          $addFields: {
            authorImage: { $arrayElemAt: ["$authorDetails.image", 0] }
          }
        },
        {
          $project: {
            _id: 1,
            title: 1,
            author: 1,
            authorImage: 1,
            createdAt: 1,
            views: { $ifNull: ["$views", 0] },
            likes: { $size: { $ifNull: ["$likes", []] } },
            readTime: {
              $concat: [
                {
                  $toString: {
                    $ceil: {
                      $divide: [
                        { $size: { $split: ["$body", " "] } },
                        200
                      ]
                    }
                  }
                },
                " min read"
              ]
            }
          }
        }
      ]);

      // Format the trending posts for display
      const formattedTrendingPosts = trendingPosts.map((post, index) => ({
        number: (index + 1).toString().padStart(2, '0'),
        image: post.authorImage || 'https://miro.medium.com/v2/resize:fit:1400/1*psYl0y9DUzZWtHzFJLIvTw.png',
        author: post.author,
        title: post.title,
        readTime: post.readTime,
        views: post.views > 999 ? `${(post.views/1000).toFixed(1)}K` : post.views.toString(),
        likes: post.likes,
        postId: post._id
      }));

      res.render("welcome", { trendingPosts: formattedTrendingPosts });
    }
  } catch (err) {
    console.error("Error fetching trending posts:", err);
    // Fallback to static data if there's an error
    const fallbackPosts = [
      {
        number: "01",
        image: "https://images.unsplash.com/photo-1517694712202-14dd9538aa97",
        author: "John Smith",
        title: "The Future of Web Development in 2024",
        readTime: "5 min read",
        views: "1.2K"
      },
      {
        number: "02",
        image: "https://images.unsplash.com/photo-1522252234503-e356532cafd5",
        author: "Sarah Johnson",
        title: "Understanding Modern JavaScript Patterns",
        readTime: "7 min read",
        views: "956"
      },
      {
        number: "03",
        image: "https://images.unsplash.com/photo-1555066931-4365d14bab8c",
        author: "David Chen",
        title: "Building Scalable Applications with Node.js",
        readTime: "8 min read",
        views: "843"
      }
    ];
    res.render("welcome", { trendingPosts: fallbackPosts });
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
    const { email, password, remember_me } = req.body;
    const user = await details.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.render("signin", {
        error: "Invalid email or password",
        values: req.body
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("signin", {
        error: "Invalid email or password",
        values: req.body
      });
    }

    // Set session
    req.session.userId = user._id;
    req.session.user = {
      name: user.name,
      username: user.username,
      email: user.email
    };

    // Handle remember me
    if (remember_me) {
      const token = crypto.randomBytes(32).toString('hex');
      user.rememberToken = token;
      await user.save();
      
      // Set remember_token cookie
      res.cookie('remember_token', token, {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
      });
    }

    // Always redirect to /blog instead of /dashboard
    return res.redirect("/blog");

  } catch (err) {
    console.error("Login error:", err);
    res.render("signin", {
      error: "Login failed. Please try again.",
      values: req.body
    });
  }
});

// Update signup route to handle image upload
app.post("/signup", upload.single('image'), async (req, res) => {
  try {
    const { name, email, username, password } = req.body;
    
    // Check if user exists
    const existingUser = await details.findOne({
      $or: [{ email: email.toLowerCase() }, { username }]
    });

    if (existingUser) {
      return res.render("signup", {
        error: "Email or username already exists",
        values: req.body
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user with optional image
    const user = new details({
      name,
      email: email.toLowerCase(),
      username,
      password: hashedPassword,
      image: req.file ? `/uploads/profiles/${req.file.filename}` : undefined
    });

    await user.save();

    // Set session
    req.session.userId = user._id;
    req.session.user = {
      name: user.name,
      username: user.username,
      email: user.email,
      image: user.image
    };

    res.redirect("/blog");
  } catch (err) {
    console.error("Signup error:", err);
    res.render("signup", {
      error: "Signup failed. Please try again.",
      values: req.body
    });
  }
});

// Routes
app.get("/", async (req, res) => {
  if (req.session.userId) {
    res.redirect('/blog');
  } else {
    res.render("signin", {
      title: "Sign In - Medium"
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

app.get("/post", checkFullAuth, async (req, res) => {
  res.render("index-5", { title: "Medium: Read and write stories" });
});
app.get("/home", (req, res) => {
  res.render("index", { title: "Medium: Read and write stories" });
});

// Dashboard Route
app.get("/dashboard", isAuthenticated, async (req, res) => {
  try {
    const user = {
      name: req.session.user.name,
      username: req.session.user.username,
      email: req.session.user.email,
      image: req.session.user.image
    };

    // Get user's blog posts with views and likes
    const userPosts = await BlogPost.find({ author: user.username })
      .select('title createdAt views likes comments') // Select specific fields
      .sort({ createdAt: -1 })
      .limit(5)
      .lean(); // Convert to plain JavaScript objects

    // Format the posts data
    const formattedPosts = userPosts.map(post => ({
      ...post,
      viewCount: post.views || 0,
      likeCount: Array.isArray(post.likes) ? post.likes.length : 0,
      commentCount: Array.isArray(post.comments) ? post.comments.length : 0,
      formattedDate: new Date(post.createdAt).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      })
    }));

    // Calculate stats using aggregation
    const [stats] = await BlogPost.aggregate([
      { $match: { author: user.username } },
      {
        $group: {
          _id: null,
          totalPosts: { $sum: 1 },
          totalViews: { 
            $sum: { 
              $cond: [
                { $ifNull: ["$views", false] },
                "$views",
                0
              ]
            }
          },
          totalLikes: {
            $sum: {
              $size: {
                $cond: [
                  { $isArray: "$likes" },
                  "$likes",
                  []
                ]
              }
            }
          },
          totalComments: {
            $sum: {
              $size: {
                $cond: [
                  { $isArray: "$comments" },
                  "$comments",
                  []
                ]
              }
            }
          }
        }
      }
    ]) || {
      totalPosts: 0,
      totalViews: 0,
      totalLikes: 0,
      totalComments: 0
    };

    res.render("index-3", {
      user,
      posts: formattedPosts,
      stats,
      title: "Dashboard - Medium"
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).render("error", {
      error: "Failed to load dashboard",
      message: "Please try again later"
    });
  }
});

// Blog Route with Category and Search Filtering
app.get("/blog", checkAuth, async (req, res) => {
  try {
    const isGuest = req.query.guest === 'true';
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
      userName: req.session.user ? req.session.user.name : 'Guest',
      groupedBlogs,
      selectedCategory,
      searchQuery,
      updateMessage: req.session.updateMessage,
      isGuest: isGuest
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
app.post("/logout", (req, res) => {
  // Clear the session
  req.session.destroy();
  
  // Clear the remember_token cookie
  res.clearCookie('remember_token');
  
  // Redirect to signin page
  res.redirect("/signin");
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
app.post('/blog/:id/like', checkFullAuth, async (req, res) => {
  try {
    const blogId = req.params.id;
    const userId = req.session.userId;
    const userName = req.session.user.name;

    const blog = await BlogPost.findById(blogId);
    if (!blog) {
      return res.status(404).json({ error: 'Blog post not found' });
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
        type: 'like',
        postTitle: blog.title,
        userName: userName
      }
    });
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
    
    // Emit notification to the post author (you'll need to implement WebSocket here)
    // For now, we'll just send it in the response
    res.json({ 
      views: blog.views,
      notification: {
        type: 'view',
        postId: blogId,
        title: blog.title
      }
    });
  } catch (err) {
    console.error('Error updating view count:', err);
    res.status(500).json({ error: 'Failed to update view count' });
  }
});

// Remember token authentication route
app.get("/auth/remember", async (req, res) => {
  try {
    if (req.cookies.remember_token) {
      const user = await details.findOne({
        rememberToken: req.cookies.remember_token
      });

      if (user) {
        req.session.userId = user._id;
        req.session.user = {
          name: user.name,
          username: user.username,
          email: user.email
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
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).render("signup", {
        error: "File is too large. Maximum size is 5MB",
        values: req.body
      });
    }
  }
  next(error);
});

// Add profile image update route
app.post("/update-profile-image", upload.single('image'), async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No image provided' });
    }

    const imageUrl = `/uploads/profiles/${req.file.filename}`;
    
    // Update user's image in database
    await details.findByIdAndUpdate(req.session.userId, {
      image: imageUrl
    });

    // Update session
    req.session.user.image = imageUrl;

    res.json({
      success: true,
      imageUrl: imageUrl
    });
  } catch (err) {
    console.error('Error updating profile image:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile image'
    });
  }
});

// Update the isAuthenticated middleware to include user data
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    // Make sure user data is available in session
    if (!req.session.user) {
      // If user data is missing, fetch it from database
      details.findById(req.session.userId)
        .then(user => {
          if (user) {
            req.session.user = {
              name: user.name,
              username: user.username,
              email: user.email,
              image: user.image
            };
            next();
          } else {
            res.redirect("/signin");
          }
        })
        .catch(err => {
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

module.exports = details;
