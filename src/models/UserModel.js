import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    lowercase: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username must be less than 30 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false // ⭐ Hide by default, but can be included with select('+password')
  },
  full_name: {
    type: String,
    required: [true, 'Full name is required'],
    trim: true
  },
  role: {
    type: String,
    enum: ['coach', 'trainee', 'admin'],
    default: 'trainee',
    required: true
  },
  profile_picture: {
    type: String,
    default: ''
  },
  bio: {
    type: String,
    default: '',
    maxlength: [500, 'Bio must be less than 500 characters']
  },
  phone_number: {
    type: String,
    default: ''
  },
  date_of_birth: {
    type: Date,
    default: null
  },
  gender: {
    type: String,
    enum: ['male', 'female', 'other', ''],
    default: ''
  },
  fitness_level: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced', ''],
    default: ''
  }
}, {
  timestamps: true
});

// Indexes
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Don't return sensitive data
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.__v;
  return user;
};

const User = mongoose.model('User', userSchema);

// Model methods
export const createUser = async (userData) => {
  const user = new User(userData);
  await user.save();
  return user;
};

export const findByEmail = async (email) => {
  return await User.findOne({ email }).select('+password');
};

export const findById = async (id) => {
  return await User.findById(id);
};

// Find users by role
export const findByRole = async (role) => {
  console.log('🔍 Finding users by role:', role);
  const users = await User.find({ role }).select('-password');
  console.log('✅ Found users:', users.length);
  return users;
};

// Search users (with optional filters)
export const searchUsers = async (filters = {}) => {
  console.log('🔍 Searching users with filters:', filters);
  const users = await User.find(filters).select('-password');
  console.log('✅ Found users:', users.length);
  return users;
};

export const updateUser = async (id, updates) => {
  return await User.findByIdAndUpdate(id, updates, { new: true, runValidators: true });
};

export const deleteUser = async (id) => {
  const result = await User.findByIdAndDelete(id);
  return !!result;
};

export const comparePassword = async (plainPassword, hashedPassword) => {
  return await bcrypt.compare(plainPassword, hashedPassword);
};

export default User;