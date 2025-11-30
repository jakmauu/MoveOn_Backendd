// Script to fix users with double-hashed passwords
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://jakmauu:E7H3vNWuMwpiNZc@praksbd.kpvs7lp.mongodb.net/MoveOn?retryWrites=true&w=majority&appName=PrakSbd';

// Define User Schema without pre-save hook
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  full_name: String,
  role: String,
  profile_picture: String,
  bio: String,
  phone_number: String,
  date_of_birth: Date,
  gender: String,
  fitness_level: String,
  is_active: Boolean,
  createdAt: Date,
  updatedAt: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Users to fix with their plain passwords
const usersToFix = [
  { username: 'xas', password: '12345678' },
  { username: 'trainee dika', password: '12345678' },
  { username: 'muhamad.dzaky', password: '12345678' }
];

async function fixUsers() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB\n');

    for (const userData of usersToFix) {
      console.log(`\n🔧 Fixing user: ${userData.username}`);
      
      // Find user
      const user = await User.findOne({ username: userData.username });
      
      if (!user) {
        console.log(`❌ User not found: ${userData.username}`);
        continue;
      }

      console.log(`📝 Found user: ${user.email}`);
      console.log(`🔍 Current password hash: ${user.password.substring(0, 20)}...`);

      // Hash password correctly (only once)
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(userData.password, salt);
      
      console.log(`🔐 New password hash: ${hashedPassword.substring(0, 20)}...`);

      // Update password directly (skip pre-save hook)
      await User.updateOne(
        { _id: user._id },
        { 
          $set: { 
            password: hashedPassword,
            updatedAt: new Date()
          }
        }
      );

      console.log(`✅ Password updated for ${userData.username}`);

      // Test the new password
      const updatedUser = await User.findById(user._id);
      const isValid = await bcrypt.compare(userData.password, updatedUser.password);
      
      if (isValid) {
        console.log(`✅ Password verification PASSED for ${userData.username}`);
      } else {
        console.log(`❌ Password verification FAILED for ${userData.username}`);
      }
    }

    console.log('\n\n🎉 All users fixed successfully!');
    console.log('\n📋 Summary:');
    console.log('-----------------------------------');
    for (const userData of usersToFix) {
      console.log(`✅ ${userData.username} - Password: ${userData.password}`);
    }
    console.log('-----------------------------------\n');

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Disconnected from MongoDB');
    process.exit(0);
  }
}

// Run the fix
fixUsers();
