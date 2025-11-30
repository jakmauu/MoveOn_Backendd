import User from '../models/UserModel.js';
import TaskAssignment from '../models/TaskAssignmentModel.js';
import { successResponse, errorResponse } from '../utils/response.js';

// ==================== PROFILE ====================

export const getTraineeProfile = async (req, res) => {
  try {
    const traineeId = req.user.id;
    
    const trainee = await User.findById(traineeId).select('-password');
    
    if (!trainee) {
      return errorResponse(res, 'Trainee not found', 404);
    }

    return successResponse(res, trainee, 'Profile retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching trainee profile:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const updateTraineeProfile = async (req, res) => {
  try {
    const traineeId = req.user.id;
    const updates = req.body;

    // Don't allow updating sensitive fields
    delete updates.password;
    delete updates.role;
    delete updates.email;
    delete updates.username;

    const trainee = await User.findByIdAndUpdate(
      traineeId,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password');

    if (!trainee) {
      return errorResponse(res, 'Trainee not found', 404);
    }

    return successResponse(res, trainee, 'Profile updated successfully');
  } catch (error) {
    console.error('❌ Error updating trainee profile:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== TASKS ====================

export const getTraineeTasks = async (req, res) => {
  try {
    const traineeId = req.user._id || req.user.id;
    const traineeIdString = traineeId.toString();
    
    console.log('📋 [GET TRAINEE TASKS] Fetching tasks for trainee:', traineeIdString);

    // Fetch ALL assignments first, then filter by string comparison
    const allAssignments = await TaskAssignment.find({})
      .populate({
        path: 'task_id',
        select: 'title description workout_type difficulty_level duration_minutes calories_target exercises created_by createdAt'
      })
      .populate({
        path: 'assigned_by',
        select: 'full_name email username'
      })
      .sort({ createdAt: -1 })
      .lean();

    console.log(`📦 Total assignments in DB: ${allAssignments.length}`);

    // Filter assignments by trainee_id
    const assignments = allAssignments.filter(a => 
      a.trainee_id && a.trainee_id.toString() === traineeIdString
    );

    console.log(`✅ Found ${assignments.length} assignments for trainee ${traineeIdString}`);

    // Get coach feedback for this trainee
    const CoachTrainee = (await import('../models/CoachTraineeModel.js')).default;
    const coachRelationships = await CoachTrainee.find({ trainee_id: traineeIdString });
    
    console.log(`📝 Found ${coachRelationships.length} coach relationships for trainee`);
    
    // Create a map of coach feedback by coach_id
    const feedbackMap = {};
    coachRelationships.forEach(rel => {
      const coachIdStr = rel.coach_id.toString();
      console.log(`👤 Coach ${coachIdStr}: notes="${rel.notes}", last_feedback_at=${rel.last_feedback_at}`);
      
      if (rel.notes) {
        feedbackMap[coachIdStr] = {
          feedback: rel.notes,
          feedback_date: rel.last_feedback_at || rel.updatedAt
        };
        console.log(`✅ Added feedback for coach ${coachIdStr}`);
      }
    });
    
    console.log(`📋 Feedback map has ${Object.keys(feedbackMap).length} entries`);

    const tasks = assignments.map(assignment => {
      const task = assignment.task_id;
      const coachId = assignment.assigned_by?._id?.toString();
      
      console.log(`🔍 Assignment ${assignment._id}: task_creator_coach="${coachId}"`);
      console.log(`   📋 Available feedback from coaches:`, Object.keys(feedbackMap));
      
      // Try to get feedback from ANY coach who has relationship with this trainee
      // Not just the coach who assigned this specific task
      let coachFeedback = null;
      
      // First try the assigning coach
      if (coachId && feedbackMap[coachId]) {
        coachFeedback = feedbackMap[coachId];
        console.log(`   ✅ Feedback from assigning coach "${coachId}": "${coachFeedback.feedback.substring(0, 50)}..."`);
      } else {
        // If no feedback from assigning coach, get feedback from ANY coach
        const anyCoachFeedback = Object.values(feedbackMap)[0];
        if (anyCoachFeedback) {
          coachFeedback = anyCoachFeedback;
          console.log(`   ✅ Feedback from another coach: "${coachFeedback.feedback.substring(0, 50)}..."`);
        } else {
          console.log(`   ❌ No feedback available from any coach`);
        }
      }
      
      return {
        assignment_id: assignment._id,
        task_id: task?._id,
        title: task?.title || 'Untitled Task',
        description: task?.description || '',
        workout_type: task?.workout_type,
        difficulty: task?.difficulty_level,
        duration: task?.duration_minutes,
        calories_target: task?.calories_target,
        exercises: task?.exercises || [],
        due_date: assignment.due_date,
        status: assignment.status,
        priority: assignment.priority,
        notes: assignment.notes,
        assigned_at: assignment.createdAt,
        completed_at: assignment.completed_at,
        coach: assignment.assigned_by ? {
          id: assignment.assigned_by._id,
          name: assignment.assigned_by.full_name,
          email: assignment.assigned_by.email,
          username: assignment.assigned_by.username
        } : null,
        coach_feedback: coachFeedback?.feedback || null,
        feedback_date: coachFeedback?.feedback_date || null
      };
    });

    const stats = {
      total: tasks.length,
      pending: tasks.filter(t => t.status === 'pending').length,
      in_progress: tasks.filter(t => t.status === 'in_progress').length,
      completed: tasks.filter(t => t.status === 'completed').length,
      overdue: tasks.filter(t => t.status === 'overdue').length
    };

    console.log('✅ Tasks stats:', stats);

    return successResponse(res, { tasks, stats }, 'Tasks retrieved successfully');

  } catch (error) {
    console.error('❌ Error fetching trainee tasks:', error);
    return errorResponse(res, error.message, 500);
  }
};

export const submitTaskCompletion = async (req, res) => {
  try {
    const traineeId = req.user.id;
    const { taskId } = req.params;
    const { notes, completion_data } = req.body;

    console.log('✅ [SUBMIT TASK] Trainee:', traineeId, 'Task:', taskId);

    const assignment = await TaskAssignment.findOne({
      task_id: taskId,
      trainee_id: traineeId
    });

    if (!assignment) {
      return errorResponse(res, 'Task assignment not found', 404);
    }

    assignment.status = 'completed';
    assignment.completed_at = new Date();
    if (notes) {
      assignment.notes = notes;
    }

    await assignment.save();

    console.log('✅ Task marked as completed');

    return successResponse(res, assignment, 'Task completed successfully');

  } catch (error) {
    console.error('❌ Error submitting task completion:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== PROGRESS ====================

export const getTraineeProgress = async (req, res) => {
  try {
    const traineeId = req.user._id || req.user.id;
    const traineeIdString = traineeId.toString();

    console.log('📊 [TRAINEE PROGRESS] Fetching progress for:', traineeIdString);

    // Fetch ALL assignments first, then filter by string comparison
    const allAssignments = await TaskAssignment.find({})
      .populate('task_id')
      .sort({ createdAt: -1 })
      .lean();

    console.log(`📦 Total assignments in DB: ${allAssignments.length}`);

    // Filter assignments by trainee_id
    const assignments = allAssignments.filter(a => 
      a.trainee_id && a.trainee_id.toString() === traineeIdString
    );

    console.log(`✅ Found ${assignments.length} assignments for trainee ${traineeIdString}`);

    const totalTasks = assignments.length;
    const completedTasks = assignments.filter(a => a.status === 'completed').length;
    const inProgressTasks = assignments.filter(a => a.status === 'in_progress').length;
    const pendingTasks = assignments.filter(a => a.status === 'pending').length;

    const completionRate = totalTasks > 0 
      ? Math.round((completedTasks / totalTasks) * 100) 
      : 0;

    const totalMinutes = assignments
      .filter(a => a.status === 'completed' && a.task_id)
      .reduce((sum, a) => sum + (a.task_id.duration_minutes || 0), 0);

    // Calculate weekly activity for the last 7 days
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const weeklyActivities = [];
    const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    
    for (let i = 6; i >= 0; i--) {
      const targetDate = new Date(today);
      targetDate.setDate(today.getDate() - i);
      const nextDate = new Date(targetDate);
      nextDate.setDate(targetDate.getDate() + 1);
      
      const dayCompletions = assignments.filter(a => 
        a.status === 'completed' && 
        a.completed_at && 
        new Date(a.completed_at) >= targetDate &&
        new Date(a.completed_at) < nextDate
      );
      
      const dayDuration = dayCompletions.reduce((sum, a) => 
        sum + (a.task_id?.duration_minutes || 0), 0
      );
      
      const dayCalories = dayCompletions.reduce((sum, a) => 
        sum + (a.task_id?.calories_target || 0), 0
      );
      
      weeklyActivities.push({
        day: dayNames[targetDate.getDay()],
        tasks: dayCompletions.length,
        duration: dayDuration,
        calories: dayCalories
      });
    }

    // Calculate streak
    let streak = 0;
    const sortedByDate = [...assignments]
      .filter(a => a.status === 'completed' && a.completed_at)
      .sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at));
    
    let currentDate = new Date();
    currentDate.setHours(0, 0, 0, 0);
    
    for (const assignment of sortedByDate) {
      const completedDate = new Date(assignment.completed_at);
      completedDate.setHours(0, 0, 0, 0);
      
      const diffDays = Math.floor((currentDate - completedDate) / (1000 * 60 * 60 * 24));
      
      if (diffDays === 0 || diffDays === 1) {
        if (diffDays === 1) {
          streak++;
          currentDate = completedDate;
        }
      } else {
        break;
      }
    }

    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const recentCompletions = assignments.filter(a => 
      a.status === 'completed' && 
      a.completed_at && 
      new Date(a.completed_at) >= sevenDaysAgo
    );

    const totalCalories = assignments
      .filter(a => a.status === 'completed' && a.task_id)
      .reduce((sum, a) => sum + (a.task_id.calories_target || 0), 0);

    const progress = {
      totalTasks: totalTasks,
      completedTasks: completedTasks,
      inProgressTasks: inProgressTasks,
      pendingTasks: pendingTasks,
      completionRate: completionRate,
      totalDuration: totalMinutes,
      totalCalories: totalCalories,
      streak: streak,
      weeklyActivities: weeklyActivities,
      statistics: {
        total_tasks: totalTasks,
        completed: completedTasks,
        in_progress: inProgressTasks,
        pending: pendingTasks,
        completion_rate: completionRate,
        total_workout_minutes: totalMinutes,
        total_workout_hours: Math.round(totalMinutes / 60 * 10) / 10
      },
      recent_activity: {
        last_7_days_completions: recentCompletions.length,
        recent_tasks: recentCompletions.slice(0, 5).map(a => ({
          task_id: a.task_id?._id,
          title: a.task_id?.title,
          completed_at: a.completed_at
        }))
      },
      upcoming_tasks: assignments
        .filter(a => a.status !== 'completed' && a.due_date)
        .sort((a, b) => new Date(a.due_date) - new Date(b.due_date))
        .slice(0, 5)
        .map(a => ({
          assignment_id: a._id,
          task_id: a.task_id?._id,
          title: a.task_id?.title,
          due_date: a.due_date,
          status: a.status
        }))
    };

    console.log('✅ Progress data calculated:', {
      totalTasks,
      completedTasks,
      streak,
      totalDuration: totalMinutes
    });

    return successResponse(res, progress, 'Progress retrieved successfully');

  } catch (error) {
    console.error('❌ Error fetching trainee progress:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== NOTIFICATIONS ====================

export const getTraineeNotifications = async (req, res) => {
  try {
    const traineeId = req.user.id;

    const threeDaysFromNow = new Date();
    threeDaysFromNow.setDate(threeDaysFromNow.getDate() + 3);

    const upcomingTasks = await TaskAssignment.find({
      trainee_id: traineeId,
      status: { $in: ['pending', 'in_progress'] },
      due_date: { $lte: threeDaysFromNow, $gte: new Date() }
    })
    .populate('task_id', 'title')
    .sort({ due_date: 1 });

    const notifications = upcomingTasks.map(assignment => ({
      type: 'task_due_soon',
      message: `Task "${assignment.task_id.title}" is due on ${new Date(assignment.due_date).toLocaleDateString()}`,
      task_id: assignment.task_id._id,
      assignment_id: assignment._id,
      due_date: assignment.due_date,
      priority: assignment.priority
    }));

    return successResponse(res, notifications, 'Notifications retrieved successfully');

  } catch (error) {
    console.error('❌ Error fetching notifications:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== COACH FEEDBACK ====================

export const getCoachFeedback = async (req, res) => {
  try {
    const traineeId = req.user.id;
    const { coachId } = req.params;

    console.log('💬 [GET FEEDBACK] Trainee:', traineeId, 'Coach:', coachId);

    const CoachTrainee = (await import('../models/CoachTraineeModel.js')).default;

    const relationship = await CoachTrainee.findOne({
      coach_id: coachId,
      trainee_id: traineeId
    });

    if (!relationship) {
      return errorResponse(res, 'Coach-trainee relationship not found', 404);
    }

    const feedbackData = {
      feedback: relationship.notes || '',
      feedback_date: relationship.last_feedback_at || relationship.updatedAt,
      coach_id: coachId
    };

    console.log('✅ Feedback retrieved');

    return successResponse(res, feedbackData, 'Feedback retrieved successfully');

  } catch (error) {
    console.error('❌ Error fetching coach feedback:', error);
    return errorResponse(res, error.message, 500);
  }
};