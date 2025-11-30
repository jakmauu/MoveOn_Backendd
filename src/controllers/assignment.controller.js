import TaskAssignment from '../models/TaskAssignmentModel.js';
import { successResponse, errorResponse } from '../utils/response.js';

// ==================== CREATE ASSIGNMENT ====================
export const createAssignment = async (req, res) => {
  try {
    const { task_id, trainee_id, due_date, priority, notes } = req.body;
    const assigned_by = req.user.id;

    console.log('📋 Creating assignment:', { task_id, trainee_id, assigned_by });

    if (!task_id || !trainee_id || !due_date) {
      return errorResponse(res, 'Task ID, Trainee ID, and Due Date are required', 400);
    }

    const assignment = new TaskAssignment({
      task_id,
      trainee_id,
      assigned_by,
      due_date,
      priority: priority || 'medium',
      notes: notes || '',
      status: 'pending'
    });

    await assignment.save();

    console.log('✅ Assignment created:', assignment._id);

    const populatedAssignment = await TaskAssignment.findById(assignment._id)
      .populate('task_id', 'title description duration_minutes')
      .populate('trainee_id', 'username full_name email')
      .populate('assigned_by', 'username full_name');

    return successResponse(res, populatedAssignment, 'Assignment created successfully', 201);
  } catch (error) {
    console.error('❌ Error creating assignment:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== GET ASSIGNMENTS BY TRAINEE ====================
export const getAssignmentsByTrainee = async (req, res) => {
  try {
    const { traineeId } = req.params;

    console.log('📋 Fetching assignments for trainee:', traineeId);

    const assignments = await TaskAssignment.find({ trainee_id: traineeId })
      .populate('task_id')
      .populate('assigned_by', 'username full_name')
      .sort({ createdAt: -1 });

    console.log(`✅ Found ${assignments.length} assignments`);

    return successResponse(res, assignments, 'Assignments retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching assignments:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== GET ASSIGNMENTS BY COACH ====================
export const getAssignmentsByCoach = async (req, res) => {
  try {
    const { coachId } = req.params;

    console.log('📋 Fetching assignments by coach:', coachId);

    const assignments = await TaskAssignment.find({ assigned_by: coachId })
      .populate('task_id')
      .populate('trainee_id', 'username full_name email')
      .sort({ createdAt: -1 });

    console.log(`✅ Found ${assignments.length} assignments`);

    return successResponse(res, assignments, 'Assignments retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching assignments:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== UPDATE ASSIGNMENT STATUS ====================
export const updateAssignmentStatus = async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const { status, notes } = req.body;

    console.log('📝 Updating assignment:', assignmentId, 'to status:', status);

    if (!status) {
      return errorResponse(res, 'Status is required', 400);
    }

    const validStatuses = ['pending', 'in_progress', 'completed', 'overdue'];
    if (!validStatuses.includes(status)) {
      return errorResponse(res, `Invalid status. Must be one of: ${validStatuses.join(', ')}`, 400);
    }

    const updateData = { status };
    if (notes !== undefined) {
      updateData.notes = notes;
    }
    if (status === 'completed') {
      updateData.completed_at = new Date();
    }

    const assignment = await TaskAssignment.findByIdAndUpdate(
      assignmentId,
      { $set: updateData },
      { new: true }
    )
      .populate('task_id')
      .populate('trainee_id', 'username full_name')
      .populate('assigned_by', 'username full_name');

    if (!assignment) {
      return errorResponse(res, 'Assignment not found', 404);
    }

    console.log('✅ Assignment updated');

    return successResponse(res, assignment, 'Assignment updated successfully');
  } catch (error) {
    console.error('❌ Error updating assignment:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== DELETE ASSIGNMENT ====================
export const deleteAssignment = async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const userId = req.user.id;

    console.log('🗑️ Deleting assignment:', assignmentId);

    // Only coach who created the assignment can delete it
    const assignment = await TaskAssignment.findOne({
      _id: assignmentId,
      assigned_by: userId
    });

    if (!assignment) {
      return errorResponse(res, 'Assignment not found or unauthorized', 404);
    }

    await TaskAssignment.findByIdAndDelete(assignmentId);

    console.log('✅ Assignment deleted');

    return successResponse(res, null, 'Assignment deleted successfully');
  } catch (error) {
    console.error('❌ Error deleting assignment:', error);
    return errorResponse(res, error.message, 500);
  }
};