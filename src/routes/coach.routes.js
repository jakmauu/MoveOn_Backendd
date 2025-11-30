import express from 'express';
import { 
  getCoachProfile, 
  updateCoachProfile, 
  getCoachTrainees,
  getAvailableTrainees,
  addTrainee,
  removeTrainee,
  getTraineeDetail,
  createAndAssignTask,
  getCoachTasks,
  getCoachAssignments,
  updateTask,
  deleteTask,
  sendFeedbackToTrainee
} from '../controllers/coach.controller.js';
import { authenticateToken, authorizeRoles } from '../middleware/authMiddleware.js';

const router = express.Router();

router.use(authenticateToken);
router.use(authorizeRoles('coach'));

// Profile
router.get('/profile', getCoachProfile);
router.put('/profile', updateCoachProfile);

// Trainees
router.get('/trainees', getCoachTrainees);
router.get('/available-trainees', getAvailableTrainees); // ⭐ New endpoint
router.get('/search-trainees', getAvailableTrainees); // Alias for backward compatibility
router.post('/trainees', addTrainee);
// ⚠️ IMPORTANT: Specific routes MUST come BEFORE dynamic :traineeId routes
router.post('/trainees/:traineeId/feedback', sendFeedbackToTrainee); // ⭐ Send feedback to trainee
router.delete('/trainees/:traineeId', removeTrainee);
router.get('/trainees/:traineeId', getTraineeDetail);

// Tasks
router.post('/:coachId/tasks', createAndAssignTask);
router.get('/tasks', getCoachTasks);
router.get('/assignments', getCoachAssignments); // ⭐ New endpoint for task assignments
router.put('/tasks/:taskId', updateTask);
router.delete('/tasks/:taskId', deleteTask);

export default router;