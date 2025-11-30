/**
 * Success response helper
 * @param {Object} res - Express response object
 * @param {*} data - Data to send
 * @param {String} message - Success message
 * @param {Number} statusCode - HTTP status code
 */
export const successResponse = (res, data = null, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json({
    success: true,
    message,
    data
  });
};

/**
 * Error response helper
 * @param {Object} res - Express response object
 * @param {String} message - Error message
 * @param {Number} statusCode - HTTP status code
 * @param {*} errors - Additional error details
 */
export const errorResponse = (res, message = 'Error', statusCode = 500, errors = null) => {
  return res.status(statusCode).json({
    success: false,
    message,
    errors
  });
};

/**
 * Paginated response helper
 * @param {Object} res - Express response object
 * @param {Array} data - Data array
 * @param {Number} page - Current page
 * @param {Number} limit - Items per page
 * @param {Number} total - Total items
 * @param {String} message - Success message
 */
export const paginatedResponse = (res, data, page, limit, total, message = 'Success') => {
  return res.status(200).json({
    success: true,
    message,
    data,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      totalPages: Math.ceil(total / limit)
    }
  });
};