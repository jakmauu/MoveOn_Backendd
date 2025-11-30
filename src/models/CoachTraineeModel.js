import mongoose from 'mongoose';

const coachTraineeSchema = new mongoose.Schema({
  coach_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Coach ID is required']
  },
  trainee_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Trainee ID is required']
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'pending'],
    default: 'active'
  },
  start_date: {
    type: Date,
    default: Date.now
  },
  end_date: {
    type: Date
  },
  notes: {
    type: String,
    trim: true
  },
  last_feedback_at: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

coachTraineeSchema.index({ coach_id: 1, status: 1 });
coachTraineeSchema.index({ trainee_id: 1, status: 1 });
coachTraineeSchema.index({ coach_id: 1, trainee_id: 1 }, { unique: true });

const CoachTrainee = mongoose.model('CoachTrainee', coachTraineeSchema);

// Model methods
export const createRelationship = async (relationshipData) => {
  const relationship = new CoachTrainee(relationshipData);
  await relationship.save();
  return relationship;
};

export const findByCoachId = async (coachId) => {
  return await CoachTrainee.find({ coach_id: coachId, status: 'active' })
    .populate('trainee_id', 'full_name email profile_picture phone_number')
    .sort({ createdAt: -1 });
};

export const findByTraineeId = async (traineeId) => {
  return await CoachTrainee.find({ trainee_id: traineeId, status: 'active' })
    .populate('coach_id', 'full_name email profile_picture phone_number')
    .sort({ createdAt: -1 });
};

export const findRelationship = async (coachId, traineeId) => {
  return await CoachTrainee.findOne({ coach_id: coachId, trainee_id: traineeId });
};

export const updateRelationship = async (id, updates) => {
  return await CoachTrainee.findByIdAndUpdate(id, updates, { new: true, runValidators: true });
};

export const deleteRelationship = async (id) => {
  const result = await CoachTrainee.findByIdAndDelete(id);
  return !!result;
};

export default CoachTrainee;