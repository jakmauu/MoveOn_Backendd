import mongoose from 'mongoose';

/**
 * Validate email format
 * @param {String} email - Email to validate
 * @returns {Boolean}
 */
export const isValidEmail = (email) => {
  const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
  return emailRegex.test(email);
};

/**
 * Validate MongoDB ObjectId
 * @param {String} id - ID to validate
 * @returns {Boolean}
 */
export const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

/**
 * Validate password strength
 * @param {String} password - Password to validate
 * @returns {Object} { valid: Boolean, message: String }
 */
export const validatePassword = (password) => {
  if (!password || password.length < 6) {
    return {
      valid: false,
      message: 'Password must be at least 6 characters long'
    };
  }
  
  return {
    valid: true,
    message: 'Password is valid'
  };
};

/**
 * Sanitize user input
 * @param {String} input - Input to sanitize
 * @returns {String}
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '');
};

/**
 * Validate required fields
 * @param {Object} data - Data object
 * @param {Array} requiredFields - Array of required field names
 * @returns {Object} { valid: Boolean, missing: Array }
 */
export const validateRequiredFields = (data, requiredFields) => {
  const missing = [];
  
  for (const field of requiredFields) {
    if (!data[field] || data[field] === '') {
      missing.push(field);
    }
  }
  
  return {
    valid: missing.length === 0,
    missing
  };
};

/**
 * Check if value is a positive integer
 * @param {*} value - Value to check
 * @returns {Boolean}
 */
export const isPositiveInteger = (value) => {
  const num = Number(value);
  return Number.isInteger(num) && num > 0;
};

/**
 * Check if value is a non-negative number
 * @param {*} value - Value to check
 * @returns {Boolean}
 */
export const isNonNegativeNumber = (value) => {
  const num = Number(value);
  return !isNaN(num) && num >= 0;
};

/**
 * Validate task data
 * @param {Object} taskData - Task data to validate
 * @returns {Object} { valid: Boolean, errors: Array }
 */
export const validateTask = (taskData) => {
  const errors = [];

  if (!taskData.title || taskData.title.trim() === '') {
    errors.push('Title is required');
  }

  if (taskData.duration_minutes && !isPositiveInteger(taskData.duration_minutes)) {
    errors.push('Duration must be a positive integer');
  }

  if (taskData.calories_target && !isNonNegativeNumber(taskData.calories_target)) {
    errors.push('Calories target must be a non-negative number');
  }

  const validTypes = ['cardio', 'strength', 'flexibility', 'balance', 'mixed'];
  if (taskData.workout_type && !validTypes.includes(taskData.workout_type)) {
    errors.push('Invalid workout type');
  }

  const validDifficulties = ['beginner', 'intermediate', 'advanced'];
  if (taskData.difficulty_level && !validDifficulties.includes(taskData.difficulty_level)) {
    errors.push('Invalid difficulty level');
  }

  return {
    valid: errors.length === 0,
    errors
  };
};

/**
 * Validate assignment data
 * @param {Object} assignmentData - Assignment data to validate
 * @returns {Object} { valid: Boolean, errors: Array }
 */
export const validateAssignment = (assignmentData) => {
  const errors = [];

  if (!assignmentData.task_id || !isValidObjectId(assignmentData.task_id)) {
    errors.push('Valid task ID is required');
  }

  if (!assignmentData.trainee_id || !isValidObjectId(assignmentData.trainee_id)) {
    errors.push('Valid trainee ID is required');
  }

  if (!assignmentData.due_date) {
    errors.push('Due date is required');
  } else {
    const dueDate = new Date(assignmentData.due_date);
    if (isNaN(dueDate.getTime())) {
      errors.push('Invalid due date format');
    }
  }

  const validPriorities = ['low', 'medium', 'high'];
  if (assignmentData.priority && !validPriorities.includes(assignmentData.priority)) {
    errors.push('Invalid priority level');
  }

  return {
    valid: errors.length === 0,
    errors
  };
};

/**
 * Validate submission data
 * @param {Object} submissionData - Submission data to validate
 * @returns {Object} { valid: Boolean, errors: Array }
 */
export const validateSubmission = (submissionData) => {
  const errors = [];

  if (!submissionData.assignment_id || !isValidObjectId(submissionData.assignment_id)) {
    errors.push('Valid assignment ID is required');
  }

  if (submissionData.duration_minutes && !isNonNegativeNumber(submissionData.duration_minutes)) {
    errors.push('Duration must be a non-negative number');
  }

  if (submissionData.calories_burned && !isNonNegativeNumber(submissionData.calories_burned)) {
    errors.push('Calories burned must be a non-negative number');
  }

  if (submissionData.rating) {
    const rating = Number(submissionData.rating);
    if (isNaN(rating) || rating < 1 || rating > 5) {
      errors.push('Rating must be between 1 and 5');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
};

/**
 * Validate template data
 * @param {Object} templateData - Template data to validate
 * @returns {Object} { valid: Boolean, errors: Array }
 */
export const validateTemplate = (templateData) => {
  const errors = [];

  if (!templateData.name || templateData.name.trim() === '') {
    errors.push('Template name is required');
  }

  const validTypes = ['cardio', 'strength', 'flexibility', 'balance', 'mixed'];
  if (templateData.workout_type && !validTypes.includes(templateData.workout_type)) {
    errors.push('Invalid workout type');
  }

  const validDifficulties = ['beginner', 'intermediate', 'advanced'];
  if (templateData.difficulty_level && !validDifficulties.includes(templateData.difficulty_level)) {
    errors.push('Invalid difficulty level');
  }

  if (templateData.duration_minutes && !isPositiveInteger(templateData.duration_minutes)) {
    errors.push('Duration must be a positive integer');
  }

  return {
    valid: errors.length === 0,
    errors
  };
};