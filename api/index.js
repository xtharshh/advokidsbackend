require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/model');

const app = express();

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());

// Disable mongoose buffering
mongoose.set('bufferCommands', false);

// Enhanced connection caching for serverless
let cachedConnection = null;

async function connectToDatabase() {
  // Return cached connection if available
  if (cachedConnection && mongoose.connection.readyState === 1) {
    console.log('♻️ Using cached MongoDB connection');
    return cachedConnection;
  }

  try {
    console.log('🔄 Creating new MongoDB connection...');
    
    const connection = await mongoose.connect(process.env.MONGODB_URI, {
      // Remove deprecated options
      maxPoolSize: 5,        // Reduced for serverless
      minPoolSize: 1,
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      retryWrites: true,
      family: 4
    });
    
    cachedConnection = connection;
    console.log('✅ MongoDB Connected Successfully!');
    return connection;
  } catch (error) {
    console.error('❌ MongoDB Connection Failed:', error.message);
    cachedConnection = null;
    throw error;
  }
}

// JWT auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ message: 'No authorization header provided' });
  }
  
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    return res.status(403).json({ message: 'Invalid token' });
  }
}

// Async handler wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Routes with connection handling

app.get('/', (req, res) => {
  res.json({ 
    message: 'ADVO-KIDS API Ready', 
    status: 'running',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', asyncHandler(async (req, res) => {
  try {
    await connectToDatabase();
    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      database: 'connected',
      mongooseState: mongoose.connection.readyState
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'ERROR', 
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error.message
    });
  }
}));

app.post('/api/register', asyncHandler(async (req, res) => {
  await connectToDatabase();

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  const existingUser = await User.findOne({ email: email.toLowerCase() });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const user = new User({ 
    email: email.toLowerCase(), 
    password: hashedPassword 
  });
  await user.save();

  const token = jwt.sign(
    { id: user._id, email: user.email }, 
    process.env.JWT_SECRET, 
    { expiresIn: '7d' }
  );

  res.status(201).json({ 
    token, 
    message: 'User registered successfully',
    user: { 
      id: user._id, 
      email: user.email, 
      points: user.points 
    }
  });
}));

app.post('/api/login', asyncHandler(async (req, res) => {
  await connectToDatabase();

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const token = jwt.sign(
    { id: user._id, email: user.email }, 
    process.env.JWT_SECRET, 
    { expiresIn: '7d' }
  );

  res.json({ 
    token, 
    message: 'Login successful',
    user: { 
      id: user._id, 
      email: user.email, 
      points: user.points 
    }
  });
}));

app.get('/api/profile', authenticateToken, asyncHandler(async (req, res) => {
  await connectToDatabase();

  const user = await User.findById(req.user.id).select('-password');
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  res.json(user);
}));

app.post('/api/points', authenticateToken, asyncHandler(async (req, res) => {
  await connectToDatabase();

  const { points } = req.body;
  if (typeof points !== 'number' || points < 0) {
    return res.status(400).json({ message: 'Points must be a positive number' });
  }
  if (points > 10000) {
    return res.status(400).json({ message: 'Maximum 10,000 points can be added at once' });
  }

  const user = await User.findById(req.user.id);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  user.points += points;
  await user.save();

  res.json({ 
    points: user.points, 
    message: 'Points updated successfully', 
    pointsAdded: points 
  });
}));

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global Error:', err);
  
  if (err.code === 11000) {
    return res.status(400).json({ message: 'Email already exists' });
  }
  
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ message: 'Invalid token' });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ message: 'Token expired' });
  }
  
  res.status(500).json({ 
    message: 'Internal server error', 
    error: process.env.NODE_ENV === 'development' ? err.message : undefined 
  });
});

// 404 handler
app.use('/*path', (req, res) => {
  res.status(404).json({ 
    message: `Route ${req.originalUrl} not found`,
    availableRoutes: [
      'GET /',
      'GET /health', 
      'POST /api/register',
      'POST /api/login',
      'GET /api/profile',
      'POST /api/points'
    ]
  });
});

// Export for Vercel
if (process.env.VERCEL) {
  module.exports = app;
} else {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 ADVO-KIDS API listening on port ${PORT}`);
  });
}
