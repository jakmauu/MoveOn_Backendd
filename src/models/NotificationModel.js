import mongoose from 'mongoose';

const notificationSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required']
  },
  type: {
    type: String,
    enum: ['task_assigned', 'task_completed', 'submission_reviewed', 'reminder', 'system'],
    required: [true, 'Notification type is required']
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true
  },
  message: {
    type: String,
    required: [true, 'Message is required'],
    trim: true
  },
  related_id: {
    type: mongoose.Schema.Types.ObjectId
  },
  is_read: {
    type: Boolean,
    default: false
  },
  read_at: {
    type: Date
  }
}, {
  timestamps: true
});

notificationSchema.index({ user_id: 1, is_read: 1 });

const Notification = mongoose.model('Notification', notificationSchema);

// Model methods
export const createNotification = async (notificationData) => {
  const notification = new Notification(notificationData);
  await notification.save();
  return notification;
};

export const findById = async (id) => {
  return await Notification.findById(id);
};

export const findByUserId = async (userId, limit = 50) => {
  return await Notification.find({ user_id: userId })
    .sort({ createdAt: -1 })
    .limit(limit);
};

export const markAsRead = async (id) => {
  return await Notification.findByIdAndUpdate(
    id,
    { is_read: true, read_at: new Date() },
    { new: true }
  );
};

export const markAllAsRead = async (userId) => {
  return await Notification.updateMany(
    { user_id: userId, is_read: false },
    { is_read: true, read_at: new Date() }
  );
};

export const deleteNotification = async (id) => {
  const result = await Notification.findByIdAndDelete(id);
  return !!result;
};

export const getUnreadCount = async (userId) => {
  return await Notification.countDocuments({ user_id: userId, is_read: false });
};

export default Notification;