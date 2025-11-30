// Test script untuk check password users
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://jakmauu:E7H3vNWuMwpiNZc@praksbd.kpvs7lp.mongodb.net/MoveOn?retryWrites=true&w=majority&appName=PrakSbd';

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  full_name: String,
  role: String,
  createdAt: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

async function testPasswords() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected\n');

    // Get all users
    const users = await User.find({}).sort({ createdAt: 1 });

    console.log('📋 All Users in Database:\n');
    console.log('='.repeat(80));

    for (const user of users) {
      console.log(`\n👤 Username: ${user.username}`);
      console.log(`📧 Email: ${user.email}`);
      console.log(`👨‍💼 Role: ${user.role}`);
      console.log(`📅 Created: ${user.createdAt}`);
      console.log(`🔐 Password Hash: ${user.password}`);
      
      // Test dengan berbagai kemungkinan password
      const testPasswords = [
        'password123',
        '12345678', 
        'trainee123',
        'coach123',
        'Password123',
        user.username + '123'
      ];

      console.log('\n🧪 Testing passwords:');
      for (const testPwd of testPasswords) {
        try {
          const isMatch = await bcrypt.compare(testPwd, user.password);
          if (isMatch) {
            console.log(`   ✅ MATCH: "${testPwd}"`);
          }
        } catch (e) {
          // Ignore
        }
      }
      
      console.log('─'.repeat(80));
    }

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

testPasswords();
