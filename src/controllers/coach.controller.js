import User from '../models/UserModel.js';
import CoachTrainee from '../models/CoachTraineeModel.js';
import { successResponse, errorResponse } from '../utils/response.js';
import { createTaskModel, deleteTaskModel } from '../models/TaskModel.js';
import { createAssignment, findByTaskId } from '../models/TaskAssignmentModel.js';

// ==================== PROFILE ====================

export const getCoachProfile = async (req, res) => {
  try {
    const coachId = req.user.id;
    
    const coach = await User.findById(coachId).select('-password');
    
    if (!coach) {
      return errorResponse(res, 'Coach not found', 404);
    }

    // Get trainee count
    const traineeCount = await CoachTrainee.countDocuments({ coach_id: coachId });

    const profileData = {
      ...coach.toObject(),
      trainee_count: traineeCount
    };

    return successResponse(res, profileData, 'Profile retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching coach profile:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const updateCoachProfile = async (req, res) => {
  try {
    const coachId = req.user.id;
    const updates = req.body;

    delete updates.password;
    delete updates.role;
    delete updates.email;
    delete updates.username;

    const coach = await User.findByIdAndUpdate(
      coachId,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password');

    if (!coach) {
      return errorResponse(res, 'Coach not found', 404);
    }

    return successResponse(res, coach, 'Profile updated successfully');
  } catch (error) {
    console.error('❌ Error updating coach profile:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== TRAINEE MANAGEMENT ====================

// Get available trainees (NOT in coach's team)
export const getAvailableTrainees = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { search } = req.query;

    console.log('🔍 Getting available trainees for coach:', coachId);
    console.log('🔍 Search term:', search);

    // Get trainee IDs already in coach's team
    const existingRelations = await CoachTrainee.find({ coach_id: coachId });
    const existingTraineeIds = existingRelations.map(rel => rel.trainee_id.toString());

    console.log('📊 Coach already has', existingTraineeIds.length, 'trainees');

    // Build query
    const query = {
      role: 'trainee',
      _id: { $nin: existingTraineeIds } // Exclude already added trainees
    };

    // Add search if provided
    if (search && search.trim()) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { full_name: { $regex: search, $options: 'i' } }
      ];
    }

    // Find available trainees
    const availableTrainees = await User.find(query)
      .select('username email full_name profile_picture fitness_level')
      .limit(50) // Limit results
      .sort({ createdAt: -1 });

    console.log('✅ Found', availableTrainees.length, 'available trainees');

    const trainees = availableTrainees.map(trainee => ({
      id: trainee._id,
      username: trainee.username,
      email: trainee.email,
      full_name: trainee.full_name,
      profile_picture: trainee.profile_picture,
      fitness_level: trainee.fitness_level
    }));

    return successResponse(res, trainees, 'Available trainees retrieved successfully');
  } catch (error) {
    console.error('❌ Error getting available trainees:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const getCoachTrainees = async (req, res) => {
  try {
    const coachId = req.user.id;
    
    console.log('📥 Fetching trainees for coach:', coachId);

    const coachTrainees = await CoachTrainee.find({ coach_id: coachId })
      .populate('trainee_id', 'username email full_name profile_picture fitness_level phone_number')
      .sort({ createdAt: -1 });

    console.log(`✅ Found ${coachTrainees.length} trainees`);

    const trainees = coachTrainees.map(ct => ({
      relationship_id: ct._id, // For deletion
      trainee_id: ct.trainee_id._id, // For navigation/detail
      username: ct.trainee_id.username,
      email: ct.trainee_id.email,
      full_name: ct.trainee_id.full_name,
      profile_picture: ct.trainee_id.profile_picture,
      fitness_level: ct.trainee_id.fitness_level,
      phone_number: ct.trainee_id.phone_number,
      status: ct.status,
      notes: ct.notes,
      start_date: ct.createdAt,
      assigned_at: ct.createdAt
    }));

    return successResponse(res, trainees, 'Trainees retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching trainees:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const addTrainee = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { trainee_id, trainee_identifier, notes } = req.body;

    console.log('➕ Adding trainee. Coach:', coachId);
    console.log('📝 Trainee ID:', trainee_id);
    console.log('📝 Trainee identifier:', trainee_identifier);

    let trainee;

    // Try by ID first (from modal selection)
    if (trainee_id) {
      trainee = await User.findOne({
        _id: trainee_id,
        role: 'trainee'
      });
    }
    // Fallback to identifier (username/email) for backward compatibility
    else if (trainee_identifier) {
      trainee = await User.findOne({
        $or: [
          { username: trainee_identifier },
          { email: trainee_identifier }
        ],
        role: 'trainee'
      });
    }

    if (!trainee_id && !trainee_identifier) {
      return errorResponse(res, 'Trainee ID or identifier is required', 400);
    }

    if (!trainee) {
      return errorResponse(res, 'Trainee not found', 404);
    }

    console.log('✅ Found trainee:', trainee.username);

    const existingRelation = await CoachTrainee.findOne({
      coach_id: coachId,
      trainee_id: trainee._id
    });

    if (existingRelation) {
      return errorResponse(res, 'Trainee already added to your team', 400);
    }

    const coachTrainee = new CoachTrainee({
      coach_id: coachId,
      trainee_id: trainee._id,
      status: 'active',
      notes: notes || ''
    });

    await coachTrainee.save();

    console.log('✅ Trainee added successfully');

    const populatedRelation = await CoachTrainee.findById(coachTrainee._id)
      .populate('trainee_id', 'username email full_name profile_picture fitness_level');

    return successResponse(res, {
      id: populatedRelation._id,
      trainee_id: populatedRelation.trainee_id._id,
      username: populatedRelation.trainee_id.username,
      email: populatedRelation.trainee_id.email,
      full_name: populatedRelation.trainee_id.full_name,
      profile_picture: populatedRelation.trainee_id.profile_picture,
      fitness_level: populatedRelation.trainee_id.fitness_level,
      status: populatedRelation.status,
      assigned_at: populatedRelation.createdAt
    }, 'Trainee added successfully', 201);

  } catch (error) {
    console.error('❌ Error adding trainee:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const removeTrainee = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { traineeId } = req.params;

    console.log('🗑️ Removing trainee:', traineeId, 'from coach:', coachId);

    const result = await CoachTrainee.findOneAndDelete({
      coach_id: coachId,
      trainee_id: traineeId
    });

    if (!result) {
      return errorResponse(res, 'Trainee relationship not found', 404);
    }

    console.log('✅ Trainee removed successfully');

    return successResponse(res, null, 'Trainee removed successfully');
  } catch (error) {
    console.error('❌ Error removing trainee:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const getTraineeDetail = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { traineeId } = req.params;

    console.log('👁️ Getting trainee detail. Coach:', coachId, 'Trainee:', traineeId);

    const relation = await CoachTrainee.findOne({
      coach_id: coachId,
      trainee_id: traineeId
    }).populate('trainee_id', '-password');

    console.log('🔍 Relation found:', relation ? 'YES' : 'NO');

    if (!relation) {
      console.log('❌ Trainee not found in coach team');
      return errorResponse(res, 'Trainee not found in your team', 404);
    }

    console.log('✅ Returning trainee:', relation.trainee_id?.username);
    return successResponse(res, relation.trainee_id, 'Trainee detail retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching trainee detail:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== TASK MANAGEMENT ====================

export const createAndAssignTask = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { title, description, duration, difficulty, dueDate, exercises, trainees } = req.body;

    console.log('📋 [CREATE & ASSIGN TASK] Starting...');
    console.log('👤 Coach ID:', coachId);
    console.log('👥 Trainees from frontend:', trainees);

    if (!title || !title.trim()) {
      return errorResponse(res, 'Task title is required', 400);
    }

    if (!trainees || !Array.isArray(trainees) || trainees.length === 0) {
      return errorResponse(res, 'At least one trainee must be selected', 400);
    }

    if (!dueDate) {
      return errorResponse(res, 'Due date is required', 400);
    }

    const difficultyMap = {
      'Beginner': 'beginner',
      'Intermediate': 'intermediate',
      'Advanced': 'advanced'
    };
    const normalizedDifficulty = difficultyMap[difficulty] || difficulty?.toLowerCase() || 'intermediate';

    console.log('✅ Validation passed');

    console.log('📝 Creating task...');
    const taskData = {
      title: title.trim(),
      description: description?.trim() || '',
      workout_type: 'custom',
      difficulty_level: normalizedDifficulty,
      duration_minutes: parseInt(duration) || 60,
      calories_target: 0,
      exercises: exercises || [],
      created_by: coachId
    };

    const task = await createTaskModel(taskData);
    console.log('✅ Task created:', task._id);

    console.log('🔍 Fetching coach trainees for verification...');
    const coachTraineeRelationships = await CoachTrainee.find({ coach_id: coachId })
      .populate('trainee_id', '_id username full_name email');

    console.log('📊 Coach has', coachTraineeRelationships.length, 'trainee relationships');

    const validTraineeIds = coachTraineeRelationships.map(rel => 
      rel.trainee_id._id.toString()
    );

    console.log('✅ Valid trainee IDs for this coach:', validTraineeIds);
    console.log('🔍 Trainees to assign:', trainees);

    const invalidTrainees = [];
    const validTraineesToAssign = [];

    for (const traineeId of trainees) {
      const traineeIdStr = traineeId.toString();
      
      if (validTraineeIds.includes(traineeIdStr)) {
        validTraineesToAssign.push(traineeIdStr);
        console.log(`✅ Trainee ${traineeIdStr} is valid`);
      } else {
        invalidTrainees.push(traineeIdStr);
        console.log(`❌ Trainee ${traineeIdStr} NOT in coach team`);
      }
    }

    if (invalidTrainees.length > 0) {
      console.error('❌ Invalid trainees found:', invalidTrainees);
      await deleteTaskModel(task._id);
      console.log('🔙 Task rolled back');
      return errorResponse(res, 'One or more trainees are not in your team', 400);
    }

    console.log('✅ All trainees verified:', validTraineesToAssign);

    console.log('📋 Creating assignments...');
    
    const assignments = await Promise.all(
      validTraineesToAssign.map(async (traineeId) => {
        const assignment = await createAssignment({
          task_id: task._id,
          trainee_id: traineeId,
          assigned_by: coachId,
          due_date: new Date(dueDate),
          priority: 'medium',
          notes: '',
          status: 'pending'
        });
        
        const trainee = coachTraineeRelationships.find(
          rel => rel.trainee_id._id.toString() === traineeId
        );
        
        return {
          assignment_id: assignment._id,
          trainee_id: traineeId,
          trainee_name: trainee?.trainee_id?.full_name || 'Unknown',
          trainee_email: trainee?.trainee_id?.email || '',
          due_date: assignment.due_date,
          status: assignment.status,
          priority: assignment.priority
        };
      })
    );

    console.log(`✅ Created ${assignments.length} assignments`);

    return successResponse(res, {
      task: {
        id: task._id,
        title: task.title,
        description: task.description,
        duration: task.duration_minutes,
        difficulty: task.difficulty_level,
        exercises: task.exercises,
        created_at: task.createdAt
      },
      assignments: assignments,
      total_assigned: assignments.length
    }, `Task created and assigned to ${assignments.length} trainee(s) successfully`, 201);

  } catch (error) {
    console.error('❌ [CREATE & ASSIGN TASK] Error:', error);
    console.error('Stack trace:', error.stack);
    return errorResponse(res, error.message || 'Error creating and assigning task', 500);
  }
};

export const getCoachTasks = async (req, res) => {
  try {
    const coachId = req.user.id;

    console.log('📋 Fetching tasks for coach:', coachId);

    const { default: Task } = await import('../models/TaskModel.js');
    
    const tasks = await Task.find({ created_by: coachId })
      .sort({ createdAt: -1 });

    console.log(`✅ Found ${tasks.length} tasks`);

    return successResponse(res, tasks, 'Tasks retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching coach tasks:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const updateTask = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { taskId } = req.params;
    const updates = req.body;

    const { default: Task } = await import('../models/TaskModel.js');

    const task = await Task.findOne({
      _id: taskId,
      created_by: coachId
    });

    if (!task) {
      return errorResponse(res, 'Task not found or unauthorized', 404);
    }

    Object.keys(updates).forEach(key => {
      if (updates[key] !== undefined) {
        task[key] = updates[key];
      }
    });

    await task.save();

    console.log('✅ Task updated:', taskId);

    return successResponse(res, task, 'Task updated successfully');
  } catch (error) {
    console.error('❌ Error updating task:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const deleteTask = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { taskId } = req.params;

    const { default: Task } = await import('../models/TaskModel.js');

    const task = await Task.findOne({
      _id: taskId,
      created_by: coachId
    });

    if (!task) {
      return errorResponse(res, 'Task not found or unauthorized', 404);
    }

    await deleteTaskModel(taskId);

    console.log('✅ Task deleted:', taskId);

    return successResponse(res, null, 'Task deleted successfully');
  } catch (error) {
    console.error('❌ Error deleting task:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const sendFeedbackToTrainee = async (req, res) => {
  try {
    console.log('🔔 [FEEDBACK] Function called!');
    console.log('🔔 [FEEDBACK] User:', req.user);
    console.log('🔔 [FEEDBACK] Params:', req.params);
    console.log('🔔 [FEEDBACK] Body:', req.body);

    const coachId = req.user.id;
    const { traineeId } = req.params;
    const { feedback } = req.body;

    console.log('📤 [FEEDBACK] Coach ID:', coachId);
    console.log('📤 [FEEDBACK] Trainee ID:', traineeId);
    console.log('📤 [FEEDBACK] Feedback text:', feedback);

    if (!feedback || !feedback.trim()) {
      console.log('❌ [FEEDBACK] Feedback is empty');
      return errorResponse(res, 'Feedback text is required', 400);
    }

    // Verify coach-trainee relationship
    console.log('🔍 [FEEDBACK] Finding relationship...');
    const relation = await CoachTrainee.findOne({
      coach_id: coachId,
      trainee_id: traineeId
    });

    console.log('🔍 [FEEDBACK] Relationship found:', relation ? 'YES' : 'NO');
    
    if (!relation) {
      console.log('❌ [FEEDBACK] No relationship found!');
      // Try to find all relationships for this coach
      const allRelations = await CoachTrainee.find({ coach_id: coachId });
      console.log('📊 [FEEDBACK] Coach has', allRelations.length, 'relationships');
      allRelations.forEach(r => {
        console.log('   - Trainee:', r.trainee_id.toString());
      });
      return errorResponse(res, 'Trainee not found in your team', 404);
    }

    console.log('📝 [FEEDBACK] Current notes:', relation.notes || 'EMPTY');
    console.log('📝 [FEEDBACK] Last feedback at:', relation.last_feedback_at || 'NULL');

    // Create or update feedback in CoachTrainee model
    relation.notes = feedback.trim();
    relation.last_feedback_at = new Date();
    
    console.log('💾 [FEEDBACK] Saving to database...');
    const saved = await relation.save();
    
    console.log('✅ [FEEDBACK] Saved successfully!');
    console.log('✅ [FEEDBACK] New notes:', saved.notes);
    console.log('✅ [FEEDBACK] New last_feedback_at:', saved.last_feedback_at);

    return successResponse(res, {
      trainee_id: traineeId,
      feedback: feedback.trim(),
      sent_at: relation.last_feedback_at
    }, 'Feedback sent successfully');
  } catch (error) {
    console.error('❌ [FEEDBACK] Error:', error);
    console.error('❌ [FEEDBACK] Stack:', error.stack);
    return errorResponse(res, error.message, 500);
  }
};

export const getCoachAssignments = async (req, res) => {
  try {
    const coachId = req.user.id;

    console.log('📋 Fetching task assignments for coach:', coachId);

    const { findByCoachId } = await import('../models/TaskAssignmentModel.js');
    
    // Get all assignments created by this coach
    const assignments = await findByCoachId(coachId);

    console.log(`✅ Found ${assignments.length} task assignments`);

    // Transform data to include necessary information
    const transformedAssignments = assignments.map(assignment => ({
      id: assignment._id,
      task_id: assignment.task_id?._id,
      task_title: assignment.task_id?.title,
      task_description: assignment.task_id?.description,
      trainee_id: assignment.trainee_id?._id,
      trainee_name: assignment.trainee_id?.full_name || assignment.trainee_id?.username,
      trainee_email: assignment.trainee_id?.email,
      status: assignment.status,
      priority: assignment.priority,
      due_date: assignment.due_date,
      completed_at: assignment.completed_at,
      assigned_at: assignment.createdAt
    }));

    return successResponse(res, transformedAssignments, 'Task assignments retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching coach assignments:', error);
    return errorResponse(res, error.message, 500);
  }
};