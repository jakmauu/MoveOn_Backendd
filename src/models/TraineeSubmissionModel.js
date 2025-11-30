import mongoose from 'mongoose';

const traineeSubmissionSchema = new mongoose.Schema({
  assignment_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'TaskAssignment',
    required: [true, 'Assignment ID is required']
  },
  trainee_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Trainee ID is required']
  },
  completion_date: {
    type: Date,
    default: Date.now
  },
  duration_minutes: {
    type: Number,
    min: [0, 'Duration cannot be negative']
  },
  calories_burned: {
    type: Number,
    min: [0, 'Calories cannot be negative']
  },
  notes: {
    type: String,
    trim: true
  },
  proof_image_url: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['submitted', 'approved', 'rejected', 'needs_revision'],
    default: 'submitted'
  },
  coach_feedback: {
    type: String,
    trim: true
  },
  rating: {
    type: Number,
    min: [1, 'Rating must be at least 1'],
    max: [5, 'Rating cannot exceed 5']
  },
  reviewed_at: {
    type: Date
  },
  reviewed_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

traineeSubmissionSchema.index({ trainee_id: 1, status: 1 });

const TraineeSubmission = mongoose.model('TraineeSubmission', traineeSubmissionSchema);

// Model methods
export const createSubmission = async (submissionData) => {
  const submission = new TraineeSubmission(submissionData);
  await submission.save();
  return submission;
};

export const findById = async (id) => {
  return await TraineeSubmission.findById(id)
    .populate('assignment_id')
    .populate('trainee_id', 'full_name email')
    .populate('reviewed_by', 'full_name email');
};

export const findByAssignmentId = async (assignmentId) => {
  return await TraineeSubmission.find({ assignment_id: assignmentId })
    .populate('trainee_id', 'full_name email')
    .sort({ createdAt: -1 });
};

export const findByTraineeId = async (traineeId) => {
  return await TraineeSubmission.find({ trainee_id: traineeId })
    .populate('assignment_id')
    .sort({ createdAt: -1 });
};

export const updateSubmission = async (id, updates) => {
  return await TraineeSubmission.findByIdAndUpdate(id, updates, { new: true, runValidators: true });
};

export const deleteSubmission = async (id) => {
  const result = await TraineeSubmission.findByIdAndDelete(id);
  return !!result;
};

export const getSubmissionsByCoach = async (coachId) => {
  const Task = mongoose.model('Task');
  const TaskAssignment = mongoose.model('TaskAssignment');
  
  const tasks = await Task.find({ coach_id: coachId });
  const taskIds = tasks.map(task => task._id);
  
  const assignments = await TaskAssignment.find({ task_id: { $in: taskIds } });
  const assignmentIds = assignments.map(assignment => assignment._id);
  
  return await TraineeSubmission.find({ assignment_id: { $in: assignmentIds } })
    .populate('assignment_id')
    .populate('trainee_id', 'full_name email')
    .sort({ createdAt: -1 });
};

export default TraineeSubmission;