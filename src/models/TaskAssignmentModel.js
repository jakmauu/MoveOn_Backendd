import mongoose from 'mongoose';

const taskAssignmentSchema = new mongoose.Schema({
  task_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Task',
    required: true
  },
  trainee_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  assigned_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  due_date: {
    type: Date,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'in_progress', 'completed', 'overdue'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  notes: {
    type: String,
    default: ''
  },
  completed_at: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Indexes
taskAssignmentSchema.index({ trainee_id: 1, status: 1 });
taskAssignmentSchema.index({ task_id: 1 });
taskAssignmentSchema.index({ assigned_by: 1 });
taskAssignmentSchema.index({ due_date: 1 });

// Auto-update status to overdue
taskAssignmentSchema.pre('save', function(next) {
  if (this.status === 'pending' || this.status === 'in_progress') {
    if (new Date() > this.due_date) {
      this.status = 'overdue';
    }
  }
  next();
});

const TaskAssignment = mongoose.model('TaskAssignment', taskAssignmentSchema);

// ==================== HELPER FUNCTIONS ====================

/**
 * Create a new assignment
 * @param {Object} assignmentData - Assignment data
 * @returns {Promise<Object>} Created assignment
 */
export const createAssignment = async (assignmentData) => {
  try {
    const assignment = new TaskAssignment(assignmentData);
    await assignment.save();
    console.log('✅ [TaskAssignment] Assignment created:', assignment._id);
    return assignment;
  } catch (error) {
    console.error('❌ [TaskAssignment] Error creating assignment:', error);
    throw error;
  }
};

/**
 * Find assignments by task ID
 * @param {String} taskId - Task ID
 * @returns {Promise<Array>} Array of assignments
 */
export const findByTaskId = async (taskId) => {
  try {
    const assignments = await TaskAssignment.find({ task_id: taskId })
      .populate('trainee_id', 'username full_name email')
      .populate('assigned_by', 'username full_name')
      .sort({ createdAt: -1 });
    return assignments;
  } catch (error) {
    console.error('❌ [TaskAssignment] Error finding by task ID:', error);
    throw error;
  }
};

/**
 * Find assignments by trainee ID
 * @param {String} traineeId - Trainee ID
 * @returns {Promise<Array>} Array of assignments
 */
export const findByTraineeId = async (traineeId) => {
  try {
    const assignments = await TaskAssignment.find({ trainee_id: traineeId })
      .populate('task_id')
      .populate('assigned_by', 'username full_name')
      .sort({ createdAt: -1 });
    return assignments;
  } catch (error) {
    console.error('❌ [TaskAssignment] Error finding by trainee ID:', error);
    throw error;
  }
};

/**
 * Find assignments by coach ID
 * @param {String} coachId - Coach ID
 * @returns {Promise<Array>} Array of assignments
 */
export const findByCoachId = async (coachId) => {
  try {
    const assignments = await TaskAssignment.find({ assigned_by: coachId })
      .populate('task_id')
      .populate('trainee_id', 'username full_name email')
      .sort({ createdAt: -1 });
    return assignments;
  } catch (error) {
    console.error('❌ [TaskAssignment] Error finding by coach ID:', error);
    throw error;
  }
};

/**
 * Update assignment status
 * @param {String} assignmentId - Assignment ID
 * @param {String} status - New status
 * @returns {Promise<Object|null>} Updated assignment
 */
export const updateAssignmentStatus = async (assignmentId, status) => {
  try {
    const assignment = await TaskAssignment.findByIdAndUpdate(
      assignmentId,
      { 
        $set: { 
          status,
          ...(status === 'completed' ? { completed_at: new Date() } : {})
        }
      },
      { new: true }
    );
    
    if (assignment) {
      console.log('✅ [TaskAssignment] Status updated:', assignmentId, 'to', status);
    }
    
    return assignment;
  } catch (error) {
    console.error('❌ [TaskAssignment] Error updating status:', error);
    throw error;
  }
};

/**
 * Delete assignment by ID
 * @param {String} assignmentId - Assignment ID
 * @returns {Promise<Object|null>} Deleted assignment
 */
export const deleteAssignment = async (assignmentId) => {
  try {
    const assignment = await TaskAssignment.findByIdAndDelete(assignmentId);
    
    if (assignment) {
      console.log('✅ [TaskAssignment] Assignment deleted:', assignmentId);
    }
    
    return assignment;
  } catch (error) {
    console.error('❌ [TaskAssignment] Error deleting assignment:', error);
    throw error;
  }
};

/**
 * Get assignment statistics for a trainee
 * @param {String} traineeId - Trainee ID
 * @returns {Promise<Object>} Statistics
 */
export const getTraineeAssignmentStats = async (traineeId) => {
  try {
    const stats = await TaskAssignment.aggregate([
      {
        $match: { trainee_id: new mongoose.Types.ObjectId(traineeId) }
      },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    const result = {
      total: 0,
      pending: 0,
      in_progress: 0,
      completed: 0,
      overdue: 0
    };

    stats.forEach(stat => {
      result[stat._id] = stat.count;
      result.total += stat.count;
    });

    return result;
  } catch (error) {
    console.error('❌ [TaskAssignment] Error getting trainee stats:', error);
    throw error;
  }
};

// Export the model as default and named export
export default TaskAssignment;
export { TaskAssignment };