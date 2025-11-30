import express from 'express';
import {
  createNewTemplate,
  getTemplates,
  getPublicTemplates,
  getTemplateById,
  updateExistingTemplate,
  deleteExistingTemplate,
  useTemplate
} from '../controllers/template.controller.js';
import { protect, authorize } from '../middleware/authMiddleware.js';

const router = express.Router();

// Public routes
router.get('/public', getPublicTemplates);

// Protected routes
router.use(protect);

// Coach-only routes
router.post('/', authorize('coach'), createNewTemplate);
router.get('/', authorize('coach'), getTemplates);
router.put('/:id', authorize('coach'), updateExistingTemplate);
router.delete('/:id', authorize('coach'), deleteExistingTemplate);

// Routes for both coach and trainee
router.get('/:id', getTemplateById);
router.post('/:id/use', useTemplate);

export default router;