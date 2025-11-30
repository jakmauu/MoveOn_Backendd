import jwt from 'jsonwebtoken';
import User from '../models/UserModel.js';

// ==================== AUTHENTICATE TOKEN ====================
export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token. User not found.'
      });
    }

    req.user = {
      _id: user._id,
      id: user._id.toString(),
      username: user.username,
      email: user.email,
      role: user.role,
      full_name: user.full_name
    };

    console.log('✅ Authenticated user:', req.user.username, 'Role:', req.user.role);
    
    next();
  } catch (error) {
    console.error('❌ Token verification error:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Internal server error during authentication'
    });
  }
};

// ==================== AUTHORIZE ROLES ====================
export const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      console.log(`❌ Access denied. User role: ${req.user.role}, Required: ${allowedRoles.join(', ')}`);
      return res.status(403).json({
        success: false,
        message: `Access denied. This route requires one of these roles: ${allowedRoles.join(', ')}`
      });
    }

    console.log(`✅ Role authorized: ${req.user.role}`);
    next();
  };
};

// ==================== OPTIONAL AUTH ====================
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select('-password');
      
      if (user) {
        req.user = {
          _id: user._id,
          id: user._id.toString(),
          username: user.username,
          email: user.email,
          role: user.role,
          full_name: user.full_name
        };
      }
    }
    
    next();
  } catch (error) {
    next();
  }
};

// ==================== VERIFY OWN RESOURCE ====================
export const verifyOwnResource = (paramName = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const resourceUserId = req.params[paramName] || req.body[paramName];
    
    if (resourceUserId && resourceUserId !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. You can only access your own resources.'
      });
    }

    next();
  };
};

export default {
  authenticateToken,
  authorizeRoles,
  optionalAuth,
  verifyOwnResource
};