import { errorResponse } from '../utils/response.js';

/**
 * Global error handler middleware
 */
export const errorHandler = (err, req, res, next) => {
  console.error('Error:', err);

  // Mongoose bad ObjectId
  if (err.name === 'CastError') {
    const message = 'Resource not found';
    return errorResponse(res, message, 404);
  }

  // Mongoose duplicate key
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const message = `${field} already exists`;
    return errorResponse(res, message, 400);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => e.message);
    return errorResponse(res, 'Validation Error', 400, errors);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return errorResponse(res, 'Invalid token', 401);
  }

  if (err.name === 'TokenExpiredError') {
    return errorResponse(res, 'Token expired', 401);
  }

  // Default error
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Server Error';

  return errorResponse(res, message, statusCode);
};

/**
 * 404 Not Found handler
 */
export const notFound = (req, res, next) => {
  const message = `Route ${req.method} ${req.originalUrl} not found`;
  return errorResponse(res, message, 404);
};