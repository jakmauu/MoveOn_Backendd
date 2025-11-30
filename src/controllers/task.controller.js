import Task from '../models/TaskModel.js';
import { successResponse, errorResponse } from '../utils/response.js';

// ==================== CREATE TASK ====================
export const createTask = async (req, res) => {
  try {
    const createdBy = req.user.id;
    const taskData = { ...req.body, created_by: createdBy };

    console.log('📝 Creating task:', taskData.title);

    const task = new Task(taskData);
    await task.save();

    console.log('✅ Task created:', task._id);

    return successResponse(res, task, 'Task created successfully', 201);
  } catch (error) {
    console.error('❌ Error creating task:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== GET ALL TASKS ====================
export const getAllTasks = async (req, res) => {
  try {
    const { page = 1, limit = 10, difficulty, workout_type, search } = req.query;

    const filter = {};

    // Apply filters
    if (difficulty) {
      filter.difficulty_level = difficulty;
    }
    if (workout_type) {
      filter.workout_type = workout_type;
    }
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;

    const [tasks, total] = await Promise.all([
      Task.find(filter)
        .populate('created_by', 'username full_name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit)),
      Task.countDocuments(filter)
    ]);

    console.log(`✅ Fetched ${tasks.length} tasks (total: ${total})`);

    return successResponse(res, {
      tasks,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / limit)
      }
    }, 'Tasks retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching tasks:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== GET MY TASKS ====================
export const getMyTasks = async (req, res) => {
  try {
    const userId = req.user.id;
    
    console.log('📋 Fetching tasks created by user:', userId);

    const tasks = await Task.find({ created_by: userId })
      .sort({ createdAt: -1 });

    console.log(`✅ Found ${tasks.length} tasks`);

    return successResponse(res, tasks, 'Tasks retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching my tasks:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== GET TASK BY ID ====================
export const getTaskById = async (req, res) => {
  try {
    const { id } = req.params;

    console.log('📋 Fetching task:', id);

    const task = await Task.findById(id)
      .populate('created_by', 'username full_name email');

    if (!task) {
      return errorResponse(res, 'Task not found', 404);
    }

    console.log('✅ Task found:', task.title);

    return successResponse(res, task, 'Task retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching task:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== UPDATE TASK ====================
export const updateTask = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;
    const updates = req.body;

    console.log('📝 Updating task:', id);

    // Find task and check ownership
    const task = await Task.findOne({ _id: id, created_by: userId });

    if (!task) {
      return errorResponse(res, 'Task not found or unauthorized', 404);
    }

    // Apply updates
    Object.keys(updates).forEach(key => {
      if (updates[key] !== undefined) {
        task[key] = updates[key];
      }
    });

    await task.save();

    console.log('✅ Task updated:', id);

    return successResponse(res, task, 'Task updated successfully');
  } catch (error) {
    console.error('❌ Error updating task:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== DELETE TASK ====================
export const deleteTask = async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    console.log('🗑️ Deleting task:', id);

    // Find and delete task (check ownership)
    const task = await Task.findOneAndDelete({ _id: id, created_by: userId });

    if (!task) {
      return errorResponse(res, 'Task not found or unauthorized', 404);
    }

    // Also delete related assignments
    const TaskAssignment = (await import('../models/TaskAssignmentModel.js')).default;
    await TaskAssignment.deleteMany({ task_id: id });

    console.log('✅ Task and related assignments deleted:', id);

    return successResponse(res, null, 'Task deleted successfully');
  } catch (error) {
    console.error('❌ Error deleting task:', error);
    return errorResponse(res, error.message, 500);
  }
};