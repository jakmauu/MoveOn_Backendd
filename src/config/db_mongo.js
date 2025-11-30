import mongoose from 'mongoose';

/**
 * Connect to MongoDB
 */
export const connectMongoDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/moveon';
    
    console.log('🔄 Connecting to MongoDB...');
    console.log('📍 URI:', mongoURI.replace(/\/\/([^:]+):([^@]+)@/, '//*****:*****@')); // Hide credentials in logs

    const conn = await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
      socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
    });

    console.log('✅ MongoDB Connected successfully');
    console.log(`📦 Database: ${conn.connection.db.databaseName}`);
    console.log(`🏠 Host: ${conn.connection.host}`);
    console.log(`🔌 Port: ${conn.connection.port}`);

    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️ MongoDB disconnected. Attempting to reconnect...');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('✅ MongoDB reconnected');
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('👋 MongoDB connection closed through app termination');
      process.exit(0);
    });

    return conn;
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    console.error('💡 Make sure MongoDB is running and the connection string is correct');
    console.error('💡 Connection string format: mongodb://username:password@host:port/database');
    process.exit(1);
  }
};

/**
 * Disconnect from MongoDB
 */
export const disconnectMongoDB = async () => {
  try {
    await mongoose.connection.close();
    console.log('✅ MongoDB disconnected successfully');
  } catch (error) {
    console.error('❌ Error disconnecting from MongoDB:', error);
    throw error;
  }
};

/**
 * Check if MongoDB is connected
 */
export const isMongoDBConnected = () => {
  return mongoose.connection.readyState === 1;
};

/**
 * Get MongoDB connection status
 */
export const getMongoDBStatus = () => {
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting',
  };
  
  return {
    state: states[mongoose.connection.readyState],
    readyState: mongoose.connection.readyState,
    host: mongoose.connection.host,
    port: mongoose.connection.port,
    database: mongoose.connection.db?.databaseName,
  };
};

export default {
  connectMongoDB,
  disconnectMongoDB,
  isMongoDBConnected,
  getMongoDBStatus,
};
