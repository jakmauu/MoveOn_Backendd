import express from 'express';
import {
  getCoachDashboard,
  getTraineeDashboard
} from '../controllers/dashboard.controller.js';
import { authenticateToken } from '../middleware/authMiddleware.js';

const router = express.Router();

// All routes require authentication
router.use(authenticateToken);

// Dashboard routes
router.get('/coach', getCoachDashboard);
router.get('/trainee', getTraineeDashboard);

export default router;