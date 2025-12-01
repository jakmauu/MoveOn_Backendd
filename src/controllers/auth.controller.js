import User from '../models/UserModel.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { successResponse, errorResponse } from '../utils/response.js';

// Generate JWT Token
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user._id.toString(), 
      username: user.username,
      email: user.email,
      role: user.role 
    },
    process.env.JWT_SECRET || 'your-secret-key-change-this',
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// Generate Refresh Token
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id.toString() },
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET || 'your-refresh-secret',
    { expiresIn: '30d' }
  );
};

// ==================== LOGIN (SUPER SIMPLE) ====================
export const login = async (req, res) => {
  try {
    const identifier = (req.body.username || req.body.email || '').toLowerCase();
    const password = req.body.password || '';

    console.log('🔐 [LOGIN] Attempt for:', identifier);
    console.log('📝 [LOGIN] Request body:', req.body);
    console.log('🔑 [LOGIN] Headers:', req.headers);

    if (!identifier || !password) {
      return errorResponse(res, 'Username and password are required', 400);
    }

    // FORCE INCLUDE PASSWORD - explicit select
    const user = await User.findOne({
      $or: [
        { username: identifier },
        { email: identifier }
      ]
    }).select('+password'); // ⭐ FORCE include password

    if (!user) {
      console.log('❌ [LOGIN] User not found');
      return errorResponse(res, 'Invalid username or password', 401);
    }

    console.log('✅ [LOGIN] User found:', user.username);
    console.log('🔍 [LOGIN] Has password:', !!user.password);

    // Simple password check
    if (!user.password) {
      console.error('❌ [LOGIN] No password in DB');
      return errorResponse(res, 'Invalid username or password', 401);
    }

    // Compare password
    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      console.log('❌ [LOGIN] Wrong password');
      return errorResponse(res, 'Invalid username or password', 401);
    }

    console.log('✅ [LOGIN] Password OK');

    // Generate tokens
    const token = generateToken(user);
    const refreshToken = generateRefreshToken(user);

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000
    });

    // Return data
    const userData = {
      id: user._id,
      username: user.username,
      email: user.email,
      full_name: user.full_name,
      role: user.role,
      profile_picture: user.profile_picture || '',
      token,
      refreshToken
    };

    console.log('✅ [LOGIN] SUCCESS');

    return successResponse(res, userData, 'Login successful');

  } catch (error) {
    console.error('❌ [LOGIN] Error:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== REGISTER (SIMPLE) ====================
export const register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body || {};
    const fullName = req.body.fullName || req.body.full_name;

    if (!username || !email || !password || !fullName) {
      return res.status(400).json({ success: false, message: 'username, email, password, full_name wajib' });
    }

    const normalizedUsername = username.toLowerCase();
    const normalizedEmail = email.toLowerCase();

    const existing = await User.findOne({ $or: [{ username: normalizedUsername }, { email: normalizedEmail }] });
    if (existing) {
      return res.status(409).json({ success: false, message: 'User dengan username/email sudah ada' });
    }

    const user = await User.create({
      username: normalizedUsername,
      email: normalizedEmail,
      password,
      role,
      full_name: fullName
    });

    return res.status(201).json({
      success: true,
      message: 'User created',
      data: { id: user._id, username: user.username, email: user.email }
    });
  } catch (err) {
    console.error('[REGISTER] Error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

// ==================== LOGOUT ====================
export const logout = async (req, res) => {
  try {
    return successResponse(res, null, 'Logout successful');
  } catch (error) {
    return errorResponse(res, error.message, 500);
  }
};

// ==================== GET ME ====================
export const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    
    if (!user) {
      return errorResponse(res, 'User not found', 404);
    }

    return successResponse(res, user, 'User data retrieved');
  } catch (error) {
    return errorResponse(res, error.message, 500);
  }
};

// ==================== REFRESH TOKEN ====================
export const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return errorResponse(res, 'Refresh token required', 400);
    }

    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET
    );

    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return errorResponse(res, 'User not found', 404);
    }

    const newToken = generateToken(user);
    const newRefreshToken = generateRefreshToken(user);

    return successResponse(res, {
      token: newToken,
      refreshToken: newRefreshToken
    }, 'Token refreshed');

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return errorResponse(res, 'Invalid token', 401);
    }
    if (error.name === 'TokenExpiredError') {
      return errorResponse(res, 'Token expired', 401);
    }
    return errorResponse(res, error.message, 500);
  }
};

// ==================== CHANGE PASSWORD ====================
export const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return errorResponse(res, 'Both passwords required', 400);
    }

    if (newPassword.length < 6) {
      return errorResponse(res, 'Password min 6 chars', 400);
    }

    const user = await User.findById(req.user.id).select('+password');
    
    if (!user) {
      return errorResponse(res, 'User not found', 404);
    }

    const isValid = await bcrypt.compare(currentPassword, user.password);
    
    if (!isValid) {
      return errorResponse(res, 'Wrong current password', 401);
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    return successResponse(res, null, 'Password changed');

  } catch (error) {
    return errorResponse(res, error.message, 500);
  }
};

// ==================== FORGOT PASSWORD ====================
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return errorResponse(res, 'Email required', 400);
    }

    return successResponse(res, null, 'Reset link sent if email exists');

  } catch (error) {
    return errorResponse(res, error.message, 500);
  }
};