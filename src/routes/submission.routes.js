import express from 'express';
import {
  submitTask,
  getMySubmissions,
  getSubmissionById,
  updateMySubmission,
  getCoachSubmissions,
  getAssignmentSubmissions,
  getTraineeSubmissions,
  reviewSubmission,
  deleteSubmission
} from '../controllers/submission.controller.js';
import { authenticateToken, authorizeRoles } from '../middleware/authMiddleware.js';

const router = express.Router();

// All routes require authentication
router.use(authenticateToken);

// ==================== TRAINEE ROUTES ====================

// Submit a task
router.post('/', authorizeRoles('trainee'), submitTask);

// Get my submissions
router.get('/my-submissions', authorizeRoles('trainee'), getMySubmissions);

// Get specific submission
router.get('/:submissionId', getSubmissionById);

// Update my submission
router.put('/:submissionId', authorizeRoles('trainee'), updateMySubmission);

// ==================== COACH ROUTES ====================

// Get all submissions for coach's tasks
router.get('/coach/all', authorizeRoles('coach'), getCoachSubmissions);

// Get submissions for specific trainee
router.get('/trainee/:traineeId', authorizeRoles('coach'), getTraineeSubmissions);

// Get submissions for specific assignment
router.get('/assignment/:assignmentId', getAssignmentSubmissions);

// Review submission (approve/reject)
router.patch('/:submissionId/review', authorizeRoles('coach'), reviewSubmission);

// ==================== SHARED ROUTES ====================

// Delete submission
router.delete('/:submissionId', deleteSubmission);

export default router;
