import mongoose from 'mongoose';

const exerciseSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  sets: {
    type: String,
    default: ''
  },
  reps: {
    type: String,
    default: ''
  },
  duration: {
    type: String,
    default: ''
  },
  intensity: {
    type: String,
    enum: ['low', 'moderate', 'high', ''],
    default: ''
  }
}, { _id: false });

const taskSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ''
  },
  workout_type: {
    type: String,
    enum: ['strength', 'cardio', 'flexibility', 'hiit', 'custom'],
    default: 'custom'
  },
  difficulty_level: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced'],
    default: 'intermediate'
  },
  duration_minutes: {
    type: Number,
    required: true,
    min: 1
  },
  calories_target: {
    type: Number,
    default: 0
  },
  exercises: [exerciseSchema],
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

// Indexes for better query performance
taskSchema.index({ created_by: 1, createdAt: -1 });
taskSchema.index({ workout_type: 1 });
taskSchema.index({ difficulty_level: 1 });

const Task = mongoose.model('Task', taskSchema);

// ==================== HELPER FUNCTIONS ====================

/**
 * Create a new task
 * @param {Object} taskData - Task data
 * @returns {Promise<Object>} Created task
 */
export const createTaskModel = async (taskData) => {
  try {
    const task = new Task(taskData);
    await task.save();
    console.log('✅ [TaskModel] Task created:', task._id);
    return task;
  } catch (error) {
    console.error('❌ [TaskModel] Error creating task:', error);
    throw error;
  }
};

/**
 * Find task by ID
 * @param {String} taskId - Task ID
 * @returns {Promise<Object|null>} Task or null
 */
export const findTaskById = async (taskId) => {
  try {
    const task = await Task.findById(taskId).populate('created_by', 'username full_name email');
    return task;
  } catch (error) {
    console.error('❌ [TaskModel] Error finding task:', error);
    throw error;
  }
};

/**
 * Find tasks by creator
 * @param {String} creatorId - Creator user ID
 * @returns {Promise<Array>} Array of tasks
 */
export const findTasksByCreator = async (creatorId) => {
  try {
    const tasks = await Task.find({ created_by: creatorId })
      .sort({ createdAt: -1 });
    return tasks;
  } catch (error) {
    console.error('❌ [TaskModel] Error finding tasks by creator:', error);
    throw error;
  }
};

/**
 * Update task by ID
 * @param {String} taskId - Task ID
 * @param {Object} updateData - Data to update
 * @returns {Promise<Object|null>} Updated task or null
 */
export const updateTaskById = async (taskId, updateData) => {
  try {
    const task = await Task.findByIdAndUpdate(
      taskId,
      { $set: updateData },
      { new: true, runValidators: true }
    );
    
    if (task) {
      console.log('✅ [TaskModel] Task updated:', taskId);
    }
    
    return task;
  } catch (error) {
    console.error('❌ [TaskModel] Error updating task:', error);
    throw error;
  }
};

/**
 * Delete task by ID
 * @param {String} taskId - Task ID
 * @returns {Promise<Object|null>} Deleted task or null
 */
export const deleteTaskModel = async (taskId) => {
  try {
    const task = await Task.findByIdAndDelete(taskId);
    
    if (task) {
      console.log('✅ [TaskModel] Task deleted:', taskId);
      
      // Also delete related assignments
      const TaskAssignment = mongoose.model('TaskAssignment');
      await TaskAssignment.deleteMany({ task_id: taskId });
      console.log('✅ [TaskModel] Related assignments deleted for task:', taskId);
    }
    
    return task;
  } catch (error) {
    console.error('❌ [TaskModel] Error deleting task:', error);
    throw error;
  }
};

/**
 * Get all tasks with pagination
 * @param {Object} options - Query options
 * @returns {Promise<Object>} Tasks and pagination info
 */
export const getAllTasks = async (options = {}) => {
  try {
    const {
      page = 1,
      limit = 10,
      sort = { createdAt: -1 },
      filter = {}
    } = options;

    const skip = (page - 1) * limit;

    const [tasks, total] = await Promise.all([
      Task.find(filter)
        .populate('created_by', 'username full_name email')
        .sort(sort)
        .skip(skip)
        .limit(limit),
      Task.countDocuments(filter)
    ]);

    return {
      tasks,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    };
  } catch (error) {
    console.error('❌ [TaskModel] Error getting all tasks:', error);
    throw error;
  }
};

/**
 * Search tasks by title or description
 * @param {String} searchTerm - Search term
 * @param {String} creatorId - Optional creator ID filter
 * @returns {Promise<Array>} Array of matching tasks
 */
export const searchTasks = async (searchTerm, creatorId = null) => {
  try {
    const query = {
      $or: [
        { title: { $regex: searchTerm, $options: 'i' } },
        { description: { $regex: searchTerm, $options: 'i' } }
      ]
    };

    if (creatorId) {
      query.created_by = creatorId;
    }

    const tasks = await Task.find(query)
      .populate('created_by', 'username full_name email')
      .sort({ createdAt: -1 });

    return tasks;
  } catch (error) {
    console.error('❌ [TaskModel] Error searching tasks:', error);
    throw error;
  }
};

/**
 * Get task statistics for a user
 * @param {String} userId - User ID
 * @returns {Promise<Object>} Task statistics
 */
export const getTaskStatsByUser = async (userId) => {
  try {
    const stats = await Task.aggregate([
      {
        $match: { created_by: new mongoose.Types.ObjectId(userId) }
      },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          totalDuration: { $sum: '$duration_minutes' },
          avgDuration: { $avg: '$duration_minutes' },
          byDifficulty: {
            $push: '$difficulty_level'
          },
          byWorkoutType: {
            $push: '$workout_type'
          }
        }
      }
    ]);

    if (stats.length === 0) {
      return {
        total: 0,
        totalDuration: 0,
        avgDuration: 0,
        byDifficulty: {},
        byWorkoutType: {}
      };
    }

    const result = stats[0];
    
    // Count by difficulty
    const difficultyCount = result.byDifficulty.reduce((acc, level) => {
      acc[level] = (acc[level] || 0) + 1;
      return acc;
    }, {});

    // Count by workout type
    const workoutTypeCount = result.byWorkoutType.reduce((acc, type) => {
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {});

    return {
      total: result.total,
      totalDuration: result.totalDuration,
      avgDuration: Math.round(result.avgDuration),
      byDifficulty: difficultyCount,
      byWorkoutType: workoutTypeCount
    };
  } catch (error) {
    console.error('❌ [TaskModel] Error getting task stats:', error);
    throw error;
  }
};

// Export the model as default and named export
export default Task;
export { Task };