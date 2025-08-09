require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Import User model
const User = require('./models/model');

const app = express();
app.use(cors({
  origin: '*', // For development only
  credentials: true
}));
app.use(bodyParser.json());

// Enhanced MongoDB connection
async function connectToMongoDB() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      bufferCommands: false,           // Disable buffering to get immediate errors
      serverSelectionTimeoutMS: 5000, // Reduce timeout to 5 seconds
      socketTimeoutMS: 45000,          // Socket timeout
      maxPoolSize: 10,                 // Maintain up to 10 socket connections
      connectTimeoutMS: 10000,         // Give up initial connection after 10 seconds
      family: 4                        // Use IPv4, skip trying IPv6
    });
    console.log('✅ MongoDB Connected Successfully!');
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    console.log('🔄 Retrying connection in 5 seconds...');
    setTimeout(connectToMongoDB, 5000);
  }
}

// Connect before starting server
connectToMongoDB();

// Monitor connection events
mongoose.connection.on('connected', () => {
  console.log('✅ Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ Mongoose connection error:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB disconnected. Attempting to reconnect...');
  connectToMongoDB();
});

// Add middleware to check database connection before processing requests
app.use((req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(500).json({ 
      message: 'Database connection unavailable',
      readyState: mongoose.connection.readyState,
      tip: 'Server is trying to reconnect to database'
    });
  }
  next();
});

// JWT auth middleware
function authenticateToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ message: 'No token provided' });
  
  const token = auth.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Invalid token format' });
  
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// Routes

// Register
app.post('/api/register', async (req, res) => {
  try {
    // Check if database is connected
    if (mongoose.connection.readyState !== 1) {
      return res.status(500).json({ 
        message: 'Database connection unavailable' 
      });
    }

    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Missing email or password' });
    }

    // Set a timeout for the database operation
    const existingUser = await User.findOne({ email }).maxTimeMS(5000);
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hash });
    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token, message: 'User registered successfully' });
  } catch (error) {
    console.error('Register error:', error);
    if (error.name === 'MongoTimeoutError' || error.message.includes('buffering timed out')) {
      return res.status(500).json({ message: 'Database operation timed out' });
    }
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    // Check if database is connected
    if (mongoose.connection.readyState !== 1) {
      return res.status(500).json({ 
        message: 'Database connection unavailable' 
      });
    }

    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Missing email or password' });

    const user = await User.findOne({ email }).maxTimeMS(5000);
    if (!user)
      return res.status(400).json({ message: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, message: 'Login successful' });
  } catch (error) {
    console.error('Login error:', error);
    if (error.name === 'MongoTimeoutError' || error.message.includes('buffering timed out')) {
      return res.status(500).json({ message: 'Database operation timed out' });
    }
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id, '-password').maxTimeMS(5000);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    console.error('Profile error:', error);
    if (error.name === 'MongoTimeoutError' || error.message.includes('buffering timed out')) {
      return res.status(500).json({ message: 'Database operation timed out' });
    }
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Add points
app.post('/api/points', authenticateToken, async (req, res) => {
  try {
    const { points } = req.body;
    if (typeof points !== 'number' || points < 0)
      return res.status(400).json({ message: 'Points must be a positive number' });

    const user = await User.findById(req.user.id).maxTimeMS(5000);
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    user.points += points;
    await user.save();
    res.json({ points: user.points, message: 'Points updated successfully' });
  } catch (error) {
    console.error('Points error:', error);
    if (error.name === 'MongoTimeoutError' || error.message.includes('buffering timed out')) {
      return res.status(500).json({ message: 'Database operation timed out' });
    }
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Root
app.get('/', (req, res) => res.json({ message: 'ADVO-KIDS API Ready', status: 'running' }));

// Health check
app.get('/health', (req, res) => res.json({ status: 'OK', timestamp: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 API listening on port ${PORT}`));
