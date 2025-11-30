import express from 'express';
import {
  getTraineeProfile,
  updateTraineeProfile,
  getTraineeTasks,
  submitTaskCompletion,
  getTraineeProgress,
  getTraineeNotifications,
  getCoachFeedback
} from '../controllers/trainee.controller.js';
import { authenticateToken, authorizeRoles } from '../middleware/authMiddleware.js';

const router = express.Router();

// All routes require authentication and trainee role
router.use(authenticateToken);
router.use(authorizeRoles('trainee'));

// Profile routes
router.get('/profile', getTraineeProfile);
router.put('/profile', updateTraineeProfile);

// Task routes
router.get('/tasks', getTraineeTasks); // ⭐ Get assigned tasks
router.post('/tasks/:taskId/submit', submitTaskCompletion); // Submit task completion

// Progress routes
router.get('/progress', getTraineeProgress);

// Notification routes
router.get('/notifications', getTraineeNotifications);

// Coach Feedback routes
router.get('/coach/:coachId/feedback', getCoachFeedback);

export default router;