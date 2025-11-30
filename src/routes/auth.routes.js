import express from 'express';
import { 
  register, 
  login, 
  logout, 
  getMe, 
  refreshToken,
  changePassword,
  forgotPassword
} from '../controllers/auth.controller.js';
import { authenticateToken } from '../middleware/authMiddleware.js';

const router = express.Router();

// ==================== PUBLIC ROUTES (NO RATE LIMITING) ====================
router.post('/register', register);
router.post('/login', login); // ⭐ NO rate limiting
router.post('/refresh', refreshToken);
router.post('/forgot-password', forgotPassword);

// ==================== PROTECTED ROUTES ====================
router.use(authenticateToken);

router.post('/logout', logout);
router.get('/me', getMe);
router.post('/change-password', changePassword);

export default router;