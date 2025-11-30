import {
  createNotification,
  findById,
  findByUserId,
  markAsRead,
  markAllAsRead,
  deleteNotification,
  getUnreadCount
} from '../models/NotificationModel.js';
import { successResponse, errorResponse } from '../utils/response.js';
import { isValidObjectId } from '../utils/validator.js';

// @desc    Get all notifications for user
// @route   GET /api/notifications
export const getNotifications = async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 50 } = req.query;

    const notifications = await findByUserId(userId, parseInt(limit));

    return successResponse(res, notifications);

  } catch (error) {
    console.error('Get notifications error:', error);
    return errorResponse(res, error.message || 'Error fetching notifications', 500);
  }
};

// @desc    Get unread count
// @route   GET /api/notifications/unread-count
export const getUnreadNotificationsCount = async (req, res) => {
  try {
    const userId = req.user.id;

    const count = await getUnreadCount(userId);

    return successResponse(res, { count });

  } catch (error) {
    console.error('Get unread count error:', error);
    return errorResponse(res, error.message || 'Error fetching unread count', 500);
  }
};

// @desc    Mark notification as read
// @route   PUT /api/notifications/:id/read
export const markNotificationAsRead = async (req, res) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      return errorResponse(res, 'Invalid notification ID', 400);
    }

    const notification = await findById(id);

    if (!notification) {
      return errorResponse(res, 'Notification not found', 404);
    }

    // Check if notification belongs to user
    if (notification.user_id.toString() !== req.user.id) {
      return errorResponse(res, 'Not authorized', 403);
    }

    const updatedNotification = await markAsRead(id);

    return successResponse(res, updatedNotification, 'Notification marked as read');

  } catch (error) {
    console.error('Mark as read error:', error);
    return errorResponse(res, error.message || 'Error marking notification as read', 500);
  }
};

// @desc    Mark all notifications as read
// @route   PUT /api/notifications/read-all
export const markAllNotificationsAsRead = async (req, res) => {
  try {
    const userId = req.user.id;

    await markAllAsRead(userId);

    return successResponse(res, null, 'All notifications marked as read');

  } catch (error) {
    console.error('Mark all as read error:', error);
    return errorResponse(res, error.message || 'Error marking all as read', 500);
  }
};

// @desc    Delete notification
// @route   DELETE /api/notifications/:id
export const deleteNotificationById = async (req, res) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      return errorResponse(res, 'Invalid notification ID', 400);
    }

    const notification = await findById(id);

    if (!notification) {
      return errorResponse(res, 'Notification not found', 404);
    }

    // Check if notification belongs to user
    if (notification.user_id.toString() !== req.user.id) {
      return errorResponse(res, 'Not authorized', 403);
    }

    await deleteNotification(id);

    return successResponse(res, null, 'Notification deleted');

  } catch (error) {
    console.error('Delete notification error:', error);
    return errorResponse(res, error.message || 'Error deleting notification', 500);
  }
};

// @desc    Create notification (internal use)
export const createNewNotification = async (userId, notificationData) => {
  try {
    notificationData.user_id = userId;
    return await createNotification(notificationData);
  } catch (error) {
    console.error('Create notification error:', error);
    throw error;
  }
};