import TraineeSubmission, { 
  createSubmission, 
  findById, 
  findByAssignmentId,
  findByTraineeId,
  updateSubmission,
  getSubmissionsByCoach
} from '../models/TraineeSubmissionModel.js';
import TaskAssignment from '../models/TaskAssignmentModel.js';
import { updateAssignmentStatus } from '../models/TaskAssignmentModel.js';
import { successResponse, errorResponse } from '../utils/response.js';

// ==================== TRAINEE ACTIONS ====================

// Submit a task (trainee completes an assignment)
export const submitTask = async (req, res) => {
  try {
    const traineeId = req.user._id || req.user.id;
    const { 
      assignment_id, 
      duration_minutes, 
      calories_burned, 
      notes, 
      proof_image_url 
    } = req.body;

    console.log('📝 [SUBMIT TASK] Trainee:', traineeId);
    console.log('📝 [SUBMIT TASK] Assignment:', assignment_id);

    if (!assignment_id) {
      return errorResponse(res, 'Assignment ID is required', 400);
    }

    // Check if assignment exists and belongs to trainee
    const assignment = await TaskAssignment.findById(assignment_id);
    
    if (!assignment) {
      return errorResponse(res, 'Assignment not found', 404);
    }

    if (assignment.trainee_id.toString() !== traineeId.toString()) {
      return errorResponse(res, 'Unauthorized: This assignment does not belong to you', 403);
    }

    // Check if already submitted
    const existingSubmission = await TraineeSubmission.findOne({ 
      assignment_id, 
      trainee_id: traineeId 
    });

    if (existingSubmission) {
      return errorResponse(res, 'Task already submitted', 400);
    }

    // Create submission
    const submissionData = {
      assignment_id,
      trainee_id: traineeId,
      duration_minutes: duration_minutes || 0,
      calories_burned: calories_burned || 0,
      notes: notes || '',
      proof_image_url: proof_image_url || '',
      status: 'submitted'
    };

    const submission = await createSubmission(submissionData);

    // Update assignment status to completed
    await updateAssignmentStatus(assignment_id, 'completed');

    console.log('✅ [SUBMIT TASK] Submission created:', submission._id);
    console.log('✅ [SUBMIT TASK] Assignment status updated to completed');

    const populatedSubmission = await findById(submission._id);

    return successResponse(res, populatedSubmission, 'Task submitted successfully', 201);
  } catch (error) {
    console.error('❌ Error submitting task:', error);
    return errorResponse(res, error.message, 500);
  }
};

// Get my submissions (trainee)
export const getMySubmissions = async (req, res) => {
  try {
    const traineeId = req.user.id;
    const { status } = req.query;

    console.log('📥 [GET SUBMISSIONS] Trainee:', traineeId);

    let query = { trainee_id: traineeId };
    
    if (status) {
      query.status = status;
    }

    const submissions = await TraineeSubmission.find(query)
      .populate({
        path: 'assignment_id',
        populate: {
          path: 'task_id',
          select: 'title description difficulty_level duration_minutes'
        }
      })
      .populate('reviewed_by', 'full_name email')
      .sort({ createdAt: -1 });

    console.log(`✅ Found ${submissions.length} submissions`);

    return successResponse(res, submissions, 'Submissions retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching submissions:', error);
    return errorResponse(res, error.message, 500);
  }
};

// Get submission by ID (trainee)
export const getSubmissionById = async (req, res) => {
  try {
    const traineeId = req.user.id;
    const { submissionId } = req.params;

    const submission = await findById(submissionId);

    if (!submission) {
      return errorResponse(res, 'Submission not found', 404);
    }

    // Check ownership
    if (submission.trainee_id._id.toString() !== traineeId) {
      return errorResponse(res, 'Unauthorized', 403);
    }

    return successResponse(res, submission, 'Submission retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching submission:', error);
    return errorResponse(res, error.message, 500);
  }
};

// Update my submission (trainee - before review)
export const updateMySubmission = async (req, res) => {
  try {
    const traineeId = req.user.id;
    const { submissionId } = req.params;
    const updates = req.body;

    const submission = await TraineeSubmission.findById(submissionId);

    if (!submission) {
      return errorResponse(res, 'Submission not found', 404);
    }

    if (submission.trainee_id.toString() !== traineeId) {
      return errorResponse(res, 'Unauthorized', 403);
    }

    // Can only update if not yet reviewed or needs revision
    if (submission.status === 'approved' || submission.status === 'rejected') {
      return errorResponse(res, 'Cannot update reviewed submission', 400);
    }

    const allowedUpdates = ['duration_minutes', 'calories_burned', 'notes', 'proof_image_url'];
    const updateData = {};
    
    allowedUpdates.forEach(field => {
      if (updates[field] !== undefined) {
        updateData[field] = updates[field];
      }
    });

    const updatedSubmission = await updateSubmission(submissionId, updateData);

    return successResponse(res, updatedSubmission, 'Submission updated successfully');
  } catch (error) {
    console.error('❌ Error updating submission:', error);
    return errorResponse(res, error.message, 500);
  }
};

// ==================== COACH ACTIONS ====================

// Get all submissions for coach's assignments
export const getCoachSubmissions = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { status, trainee_id } = req.query;

    console.log('📥 [COACH SUBMISSIONS] Coach:', coachId);

    const submissions = await getSubmissionsByCoach(coachId);

    // Filter by status if provided
    let filteredSubmissions = submissions;
    
    if (status) {
      filteredSubmissions = filteredSubmissions.filter(s => s.status === status);
    }

    if (trainee_id) {
      filteredSubmissions = filteredSubmissions.filter(
        s => s.trainee_id._id.toString() === trainee_id
      );
    }

    console.log(`✅ Found ${filteredSubmissions.length} submissions`);

    return successResponse(res, filteredSubmissions, 'Submissions retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching coach submissions:', error);
    return errorResponse(res, error.message, 500);
  }
};

// Get submissions for specific assignment
export const getAssignmentSubmissions = async (req, res) => {
  try {
    const { assignmentId } = req.params;

    console.log('📥 [ASSIGNMENT SUBMISSIONS] Assignment:', assignmentId);

    const submissions = await findByAssignmentId(assignmentId);

    console.log(`✅ Found ${submissions.length} submissions`);

    return successResponse(res, submissions, 'Submissions retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching assignment submissions:', error);
    return errorResponse(res, error.message, 500);
  }
};

// Get submissions for specific trainee (coach view)
export const getTraineeSubmissions = async (req, res) => {
  try {
    const { traineeId } = req.params;
    const coachId = req.user.id;

    console.log('📥 [TRAINEE SUBMISSIONS] Coach:', coachId, 'Trainee:', traineeId);

    // TODO: Verify coach has access to this trainee
    
    const submissions = await findByTraineeId(traineeId);

    console.log(`✅ Found ${submissions.length} submissions`);

    return successResponse(res, submissions, 'Submissions retrieved successfully');
  } catch (error) {
    console.error('❌ Error fetching trainee submissions:', error);
    return errorResponse(res, error.message, 500);
  }
};

// Review submission (coach - approve/reject)
export const reviewSubmission = async (req, res) => {
  try {
    const coachId = req.user.id;
    const { submissionId } = req.params;
    const { status, coach_feedback, rating } = req.body;

    console.log('🔍 [REVIEW SUBMISSION] Coach:', coachId);
    console.log('🔍 [REVIEW SUBMISSION] Submission:', submissionId);
    console.log('🔍 [REVIEW SUBMISSION] Status:', status);

    if (!status || !['approved', 'rejected', 'needs_revision'].includes(status)) {
      return errorResponse(res, 'Valid status is required (approved/rejected/needs_revision)', 400);
    }

    const submission = await TraineeSubmission.findById(submissionId)
      .populate({
        path: 'assignment_id',
        populate: {
          path: 'task_id'
        }
      });

    if (!submission) {
      return errorResponse(res, 'Submission not found', 404);
    }

    // Verify coach owns the task
    if (submission.assignment_id.task_id.coach_id.toString() !== coachId) {
      return errorResponse(res, 'Unauthorized: You cannot review this submission', 403);
    }

    const updates = {
      status,
      reviewed_by: coachId,
      reviewed_at: new Date()
    };

    if (coach_feedback) {
      updates.coach_feedback = coach_feedback;
    }

    if (rating) {
      if (rating < 1 || rating > 5) {
        return errorResponse(res, 'Rating must be between 1 and 5', 400);
      }
      updates.rating = rating;
    }

    const updatedSubmission = await updateSubmission(submissionId, updates);

    console.log('✅ [REVIEW SUBMISSION] Reviewed successfully');

    return successResponse(res, updatedSubmission, 'Submission reviewed successfully');
  } catch (error) {
    console.error('❌ Error reviewing submission:', error);
    return errorResponse(res, error.message, 500);
  }
};

// Delete submission
export const deleteSubmission = async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;
    const { submissionId } = req.params;

    const submission = await TraineeSubmission.findById(submissionId);

    if (!submission) {
      return errorResponse(res, 'Submission not found', 404);
    }

    // Trainee can delete their own, coach can delete any
    if (userRole === 'trainee' && submission.trainee_id.toString() !== userId) {
      return errorResponse(res, 'Unauthorized', 403);
    }

    await TraineeSubmission.findByIdAndDelete(submissionId);

    console.log('✅ Submission deleted:', submissionId);

    return successResponse(res, null, 'Submission deleted successfully');
  } catch (error) {
    console.error('❌ Error deleting submission:', error);
    return errorResponse(res, error.message, 500);
  }
};
