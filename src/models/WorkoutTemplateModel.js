import mongoose from 'mongoose';

const workoutTemplateSchema = new mongoose.Schema({
  coach_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Coach ID is required']
  },
  name: {
    type: String,
    required: [true, 'Template name is required'],
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  workout_type: {
    type: String,
    enum: ['cardio', 'strength', 'flexibility', 'balance', 'mixed'],
    default: 'mixed'
  },
  difficulty_level: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced'],
    default: 'beginner'
  },
  duration_minutes: {
    type: Number,
    min: [1, 'Duration must be at least 1 minute']
  },
  exercises: [{
    name: {
      type: String,
      required: true,
      trim: true
    },
    sets: Number,
    reps: Number,
    duration_seconds: Number,
    rest_seconds: Number,
    notes: String
  }],
  equipment_needed: [{
    type: String,
    trim: true
  }],
  is_public: {
    type: Boolean,
    default: false
  },
  is_active: {
    type: Boolean,
    default: true
  },
  usage_count: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

workoutTemplateSchema.index({ coach_id: 1, is_active: 1 });

const WorkoutTemplate = mongoose.model('WorkoutTemplate', workoutTemplateSchema);

// Model methods
export const createTemplate = async (templateData) => {
  const template = new WorkoutTemplate(templateData);
  await template.save();
  return template;
};

export const findById = async (id) => {
  return await WorkoutTemplate.findById(id).populate('coach_id', 'full_name email');
};

export const findByCoachId = async (coachId) => {
  return await WorkoutTemplate.find({ coach_id: coachId, is_active: true })
    .sort({ createdAt: -1 });
};

export const updateTemplate = async (id, updates) => {
  return await WorkoutTemplate.findByIdAndUpdate(id, updates, { new: true, runValidators: true });
};

export const deleteTemplate = async (id) => {
  const result = await WorkoutTemplate.findByIdAndDelete(id);
  return !!result;
};

export const findPublicTemplates = async () => {
  return await WorkoutTemplate.find({ is_public: true, is_active: true })
    .populate('coach_id', 'full_name email')
    .sort({ usage_count: -1, createdAt: -1 });
};

export const incrementUsageCount = async (id) => {
  return await WorkoutTemplate.findByIdAndUpdate(
    id,
    { $inc: { usage_count: 1 } },
    { new: true }
  );
};

export default WorkoutTemplate;