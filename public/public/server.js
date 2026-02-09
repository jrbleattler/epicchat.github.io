const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/chatroom', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// Database Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profilePicture: { type: String, default: '/default-avatar.png' },
  bio: { type: String, default: '' },
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  permissions: [String],
  isBanned: { type: Boolean, default: false },
  banReason: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  lastActive: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  username: String,
  userId: mongoose.Schema.Types.ObjectId,
  message: String,
  timestamp: { type: Date, default: Date.now },
  profilePicture: String
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// Multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Utility Functions
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '7d' });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
  } catch (error) {
    return null;
  }
};

const convertImageToBase64 = (buffer) => {
  return 'data:image/jpeg;base64,' + buffer.toString('base64');
};

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Email or username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email,
      username,
      password: hashedPassword,
      role: 'user'
    });

    await user.save();
    const token = generateToken(user._id);

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        profilePicture: user.profilePicture,
        permissions: user.permissions
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    if (user.isBanned) {
      return res.status(403).json({ error: `You are banned. Reason: ${user.banReason}` });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    user.lastActive = Date.now();
    await user.save();

    const token = generateToken(user._id);

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        profilePicture: user.profilePicture,
        bio: user.bio,
        permissions: user.permissions
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Profile
app.put('/api/user/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { username, bio, profilePicture } = req.body;
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (username && username !== user.username) {
      const existing = await User.findOne({ username });
      if (existing) {
        return res.status(400).json({ error: 'Username already taken' });
      }
      user.username = username;
    }

    if (bio) user.bio = bio;
    if (profilePicture) user.profilePicture = profilePicture;

    await user.save();

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        profilePicture: user.profilePicture,
        bio: user.bio,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User
app.get('/api/user/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user._id,
      username: user.username,
      profilePicture: user.profilePicture,
      bio: user.bio,
      role: user.role,
      createdAt: user.createdAt
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get all users
app.get('/api/admin/users', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const user = await User.findById(decoded.userId);
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }

    const users = await User.find({}, '-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Ban user
app.post('/api/admin/ban-user', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const admin = await User.findById(decoded.userId);
    if (admin.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }

    const { userId, reason } = req.body;
    const userToBan = await User.findById(userId);

    if (!userToBan) {
      return res.status(404).json({ error: 'User not found' });
    }

    userToBan.isBanned = true;
    userToBan.banReason = reason || 'No reason provided';
    await userToBan.save();

    // Disconnect user from chat
    io.to(userId).emit('banned', { reason: userToBan.banReason });

    res.json({ message: 'User banned successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Unban user
app.post('/api/admin/unban-user', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const admin = await User.findById(decoded.userId);
    if (admin.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }

    const { userId } = req.body;
    const userToUnban = await User.findById(userId);

    if (!userToUnban) {
      return res.status(404).json({ error: 'User not found' });
    }

    userToUnban.isBanned = false;
    userToUnban.banReason = '';
    await userToUnban.save();

    res.json({ message: 'User unbanned successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Change user role
app.post('/api/admin/change-role', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const admin = await User.findById(decoded.userId);
    if (admin.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }

    const { userId, role } = req.body;
    if (!['user', 'moderator', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const userToUpdate = await User.findById(userId);
    if (!userToUpdate) {
      return res.status(404).json({ error: 'User not found' });
    }

    userToUpdate.role = role;
    await userToUpdate.save();

    res.json({ message: 'User role updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Assign permissions
app.post('/api/admin/permissions', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const admin = await User.findById(decoded.userId);
    if (admin.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }

    const { userId, permissions } = req.body;
    const userToUpdate = await User.findById(userId);

    if (!userToUpdate) {
      return res.status(404).json({ error: 'User not found' });
    }

    userToUpdate.permissions = permissions;
    await userToUpdate.save();

    res.json({ message: 'Permissions updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.IO Events
const userSockets = {};

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  socket.on('join', async (data) => {
    const token = data.token;
    const decoded = verifyToken(token);

    if (!decoded) {
      socket.emit('error', 'Unauthorized');
      return;
    }

    const user = await User.findById(decoded.userId);

    if (!user) {
      socket.emit('error', 'User not found');
      return;
    }

    if (user.isBanned) {
      socket.emit('banned', { reason: user.banReason });
      return;
    }

    userSockets[socket.id] = {
      userId: user._id.toString(),
      username: user.username,
      profilePicture: user.profilePicture,
      role: user.role,
      permissions: user.permissions
    };

    socket.emit('join-success', {
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        profilePicture: user.profilePicture
      }
    });

    // Load chat history
    const messages = await Message.find().sort({ timestamp: 1 }).limit(50);
    socket.emit('load-messages', messages);

    // Notify others
    io.emit('user-joined', {
      username: user.username,
      totalUsers: Object.keys(userSockets).length
    });
  });

  socket.on('send-message', async (data) => {
    const userInfo = userSockets[socket.id];

    if (!userInfo) {
      socket.emit('error', 'Not authenticated');
      return;
    }

    try {
      const message = new Message({
        username: userInfo.username,
        userId: userInfo.userId,
        message: data.message,
        profilePicture: userInfo.profilePicture
      });

      await message.save();

      io.emit('receive-message', {
        id: message._id,
        username: userInfo.username,
        userId: userInfo.userId,
        message: data.message,
        profilePicture: userInfo.profilePicture,
        role: userInfo.role,
        timestamp: message.timestamp
      });
    } catch (error) {
      socket.emit('error', 'Failed to send message');
    }
  });

  socket.on('typing', (data) => {
    socket.broadcast.emit('user-typing', {
      username: data.username
    });
  });

  socket.on('disconnect', () => {
    const userInfo = userSockets[socket.id];
    delete userSockets[socket.id];

    if (userInfo) {
      io.emit('user-left', {
        username: userInfo.username,
        totalUsers: Object.keys(userSockets).length
      });
    }

    console.log(`User disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  
  // Create default admin account if it doesn't exist
  try {
    const adminExists = await User.findOne({ username: 'EpicToast78' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('Admin123!', 10);
      const adminUser = new User({
        email: 'admin@chatroom.com',
        username: 'EpicToast78',
        password: hashedPassword,
        role: 'admin',
        profilePicture: '/default-avatar.png',
        permissions: ['ban-users', 'kick-users', 'manage-roles', 'delete-messages']
      });
      await adminUser.save();
      console.log('Admin account created: EpicToast78');
    }
  } catch (error) {
    console.log('Admin account already exists or error creating it');
  }
});
