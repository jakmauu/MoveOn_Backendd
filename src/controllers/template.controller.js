import WorkoutTemplate, {
  createTemplate,
  findById,
  findByCoachId,
  updateTemplate,
  deleteTemplate,
  findPublicTemplates,
  incrementUsageCount
} from '../models/WorkoutTemplateModel.js';
import { successResponse, errorResponse } from '../utils/response.js';
import { validateTemplate, isValidObjectId } from '../utils/validator.js';

// @desc    Create new workout template
// @route   POST /api/templates
export const createNewTemplate = async (req, res) => {
  try {
    const coachId = req.user.id;
    const templateData = req.body;

    // Validate template data
    const validation = validateTemplate(templateData);
    if (!validation.valid) {
      return errorResponse(res, 'Validation failed', 400, validation.errors);
    }

    // Add coach_id
    templateData.coach_id = coachId;

    const template = await createTemplate(templateData);

    return successResponse(res, template, 'Template created successfully', 201);

  } catch (error) {
    console.error('Create template error:', error);
    return errorResponse(res, error.message || 'Error creating template', 500);
  }
};

// @desc    Get all templates for coach
// @route   GET /api/templates
export const getTemplates = async (req, res) => {
  try {
    const coachId = req.user.id;

    const templates = await findByCoachId(coachId);

    return successResponse(res, templates);

  } catch (error) {
    console.error('Get templates error:', error);
    return errorResponse(res, error.message || 'Error fetching templates', 500);
  }
};

// @desc    Get public templates
// @route   GET /api/templates/public
export const getPublicTemplates = async (req, res) => {
  try {
    const templates = await findPublicTemplates();

    return successResponse(res, templates);

  } catch (error) {
    console.error('Get public templates error:', error);
    return errorResponse(res, error.message || 'Error fetching public templates', 500);
  }
};

// @desc    Get single template
// @route   GET /api/templates/:id
export const getTemplateById = async (req, res) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      return errorResponse(res, 'Invalid template ID', 400);
    }

    const template = await findById(id);

    if (!template) {
      return errorResponse(res, 'Template not found', 404);
    }

    return successResponse(res, template);

  } catch (error) {
    console.error('Get template by ID error:', error);
    return errorResponse(res, error.message || 'Error fetching template', 500);
  }
};

// @desc    Update template
// @route   PUT /api/templates/:id
export const updateExistingTemplate = async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    if (!isValidObjectId(id)) {
      return errorResponse(res, 'Invalid template ID', 400);
    }

    const template = await findById(id);

    if (!template) {
      return errorResponse(res, 'Template not found', 404);
    }

    // Check authorization
    if (template.coach_id.toString() !== req.user.id) {
      return errorResponse(res, 'Not authorized to update this template', 403);
    }

    const updatedTemplate = await updateTemplate(id, updates);

    return successResponse(res, updatedTemplate, 'Template updated successfully');

  } catch (error) {
    console.error('Update template error:', error);
    return errorResponse(res, error.message || 'Error updating template', 500);
  }
};

// @desc    Delete template
// @route   DELETE /api/templates/:id
export const deleteExistingTemplate = async (req, res) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      return errorResponse(res, 'Invalid template ID', 400);
    }

    const template = await findById(id);

    if (!template) {
      return errorResponse(res, 'Template not found', 404);
    }

    // Check authorization
    if (template.coach_id.toString() !== req.user.id) {
      return errorResponse(res, 'Not authorized to delete this template', 403);
    }

    await deleteTemplate(id);

    return successResponse(res, null, 'Template deleted successfully');

  } catch (error) {
    console.error('Delete template error:', error);
    return errorResponse(res, error.message || 'Error deleting template', 500);
  }
};

// @desc    Use template (increment usage count)
// @route   POST /api/templates/:id/use
export const useTemplate = async (req, res) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      return errorResponse(res, 'Invalid template ID', 400);
    }

    const template = await incrementUsageCount(id);

    if (!template) {
      return errorResponse(res, 'Template not found', 404);
    }

    return successResponse(res, template, 'Template usage recorded');

  } catch (error) {
    console.error('Use template error:', error);
    return errorResponse(res, error.message || 'Error using template', 500);
  }
};