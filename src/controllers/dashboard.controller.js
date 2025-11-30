import mongoose from 'mongoose';
import User from '../models/UserModel.js';
import CoachTrainee from '../models/CoachTraineeModel.js';
import TaskAssignment from '../models/TaskAssignmentModel.js';
import Task from '../models/TaskModel.js';
import { successResponse, errorResponse } from '../utils/response.js';

// ==================== COACH DASHBOARD ====================
export const getCoachDashboard = async (req, res) => {
  try {
    const coachId = req.user.id;

    console.log('📊 Fetching coach dashboard for:', coachId);

    // Get total trainees
    const totalTrainees = await CoachTrainee.countDocuments({ coach_id: coachId });

    // Get total tasks created
    const totalTasks = await Task.countDocuments({ created_by: coachId });

    // Get total assignments
    const totalAssignments = await TaskAssignment.countDocuments({ assigned_by: coachId });

    // Get assignments by status
    const assignmentStats = await TaskAssignment.aggregate([
      { $match: { assigned_by: coachId } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    const stats = {
      pending: 0,
      in_progress: 0,
      completed: 0,
      overdue: 0
    };

    assignmentStats.forEach(stat => {
      stats[stat._id] = stat.count;
    });

    // Get recent assignments
    const recentAssignments = await TaskAssignment.find({ assigned_by: coachId })
      .populate('task_id', 'title')
      .populate('trainee_id', 'full_name username')
      .sort({ createdAt: -1 })
      .limit(5);

    const dashboardData = {
      overview: {
        total_trainees: totalTrainees,
        total_tasks: totalTasks,
        total_assignments: totalAssignments,
        assignment_stats: stats
      },
      recent_assignments: recentAssignments
    };

    console.log('✅ Coach dashboard data fetched');

    return successResponse(res, dashboardData, 'Dashboard data retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching coach dashboard:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== TRAINEE DASHBOARD ====================
export const getTraineeDashboard = async (req, res) => {
  try {
    // Get trainee ID from authenticated user - support both string and ObjectId
    let traineeId = req.user._id || req.user.id;
    
    // Convert to string for consistent comparison
    const traineeIdString = traineeId.toString();

    console.log('📊 [TRAINEE DASHBOARD] Fetching for traineeId:', traineeIdString);

    // Get all assignments - use string comparison to avoid ObjectId issues
    const allAssignments = await TaskAssignment.find({})
      .populate('task_id')
      .populate('assigned_by', 'full_name username')
      .lean();

    // Filter assignments for this trainee (compare as strings)
    const assignments = allAssignments.filter(a => 
      a.trainee_id && a.trainee_id.toString() === traineeIdString
    );

    console.log('✅ [TRAINEE DASHBOARD] Total assignments in DB:', allAssignments.length);
    console.log('✅ [TRAINEE DASHBOARD] Assignments for this trainee:', assignments.length);
    
    if (assignments.length > 0) {
      console.log('📋 [TRAINEE DASHBOARD] Sample assignment:', {
        _id: assignments[0]._id,
        trainee_id: assignments[0].trainee_id.toString(),
        status: assignments[0].status,
        task_title: assignments[0].task_id?.title
      });
    }

    // Calculate statistics
    const stats = {
      totalTasks: assignments.length,
      completed: 0,
      inProgress: 0,
      pending: 0,
      overdue: 0,
      totalHours: 0,
      completionRate: 0
    };

    // Count by status and calculate hours
    assignments.forEach(assignment => {
      if (assignment.status === 'completed') stats.completed++;
      else if (assignment.status === 'in_progress') stats.inProgress++;
      else if (assignment.status === 'pending') stats.pending++;
      else if (assignment.status === 'overdue') stats.overdue++;

      // Sum total hours from task duration
      if (assignment.task_id?.duration_minutes) {
        stats.totalHours += assignment.task_id.duration_minutes / 60;
      }
    });

    // Calculate completion rate
    if (stats.totalTasks > 0) {
      stats.completionRate = Math.round((stats.completed / stats.totalTasks) * 100);
    }

    // Get recent assignments (latest 5)
    const recentTasks = assignments
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 5)
      .map(assignment => ({
        _id: assignment._id,
        task: {
          _id: assignment.task_id?._id,
          title: assignment.task_id?.title || 'Untitled Task',
          description: assignment.task_id?.description || '',
          type: assignment.task_id?.workout_type,
          duration_minutes: assignment.task_id?.duration_minutes,
          difficulty: assignment.task_id?.difficulty_level
        },
        coach: assignment.assigned_by,
        status: assignment.status,
        due_date: assignment.due_date,
        completed_at: assignment.completed_at,
        createdAt: assignment.createdAt
      }));

    // Get upcoming deadlines
    const sevenDaysFromNow = new Date();
    sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);

    const upcomingDeadlines = assignments
      .filter(a => 
        (a.status === 'pending' || a.status === 'in_progress') && 
        a.due_date && 
        new Date(a.due_date) >= new Date() &&
        new Date(a.due_date) <= sevenDaysFromNow
      )
      .sort((a, b) => new Date(a.due_date) - new Date(b.due_date))
      .slice(0, 5)
      .map(assignment => ({
        _id: assignment._id,
        task: {
          _id: assignment.task_id?._id,
          title: assignment.task_id?.title || 'Untitled Task',
          duration_minutes: assignment.task_id?.duration_minutes
        },
        coach: assignment.assigned_by,
        status: assignment.status,
        due_date: assignment.due_date
      }));

    const dashboardData = {
      stats,
      recentTasks,
      upcomingDeadlines,
      allAssignments: assignments.length
    };

    console.log('✅ Trainee dashboard stats:', stats);

    return successResponse(res, dashboardData, 'Dashboard data retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching trainee dashboard:', error);
    return errorResponse(res, error.message, 500);
  }
};