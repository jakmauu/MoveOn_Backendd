import express from 'express';
import { generateMealPlan } from '../controllers/mealplan.controller.js';
import { authenticateToken } from '../middleware/authMiddleware.js';

const router = express.Router();

// All routes require authentication
router.use(authenticateToken);

// Generate meal plan
router.post('/generate', generateMealPlan);

export default router;
