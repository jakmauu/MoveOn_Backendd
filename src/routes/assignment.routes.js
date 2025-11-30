import express from 'express';
import {
  createAssignment,
  getAssignmentsByTrainee,
  getAssignmentsByCoach,
  updateAssignmentStatus,
  deleteAssignment
} from '../controllers/assignment.controller.js';
import { authenticateToken } from '../middleware/authMiddleware.js';

const router = express.Router();

// All routes require authentication
router.use(authenticateToken);

// Assignment routes
router.post('/', createAssignment);
router.get('/trainee/:traineeId', getAssignmentsByTrainee);
router.get('/coach/:coachId', getAssignmentsByCoach);
router.patch('/:assignmentId/status', updateAssignmentStatus); // Update status
router.patch('/:assignmentId', updateAssignmentStatus); // Alias for backward compatibility
router.delete('/:assignmentId', deleteAssignment);

export default router;