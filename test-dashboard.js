import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const TaskAssignmentSchema = new mongoose.Schema({
  task_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Task' },
  trainee_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  assigned_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: String,
  due_date: Date
}, { timestamps: true });

const TaskAssignment = mongoose.model('TaskAssignment', TaskAssignmentSchema);

async function testDashboard() {
  try {
    console.log('🔌 Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Get all assignments
    console.log('\n📊 Fetching all task assignments...');
    const allAssignments = await TaskAssignment.find({}).lean();
    console.log(`✅ Total assignments in DB: ${allAssignments.length}`);

    if (allAssignments.length > 0) {
      console.log('\n📋 Sample assignment:');
      console.log(JSON.stringify(allAssignments[0], null, 2));

      // Group by trainee
      const byTrainee = {};
      allAssignments.forEach(a => {
        const traineeId = a.trainee_id.toString();
        if (!byTrainee[traineeId]) {
          byTrainee[traineeId] = [];
        }
        byTrainee[traineeId].push(a);
      });

      console.log('\n👥 Assignments by trainee:');
      Object.keys(byTrainee).forEach(traineeId => {
        console.log(`  Trainee ${traineeId}: ${byTrainee[traineeId].length} tasks`);
        console.log(`    Statuses:`, byTrainee[traineeId].map(a => a.status).join(', '));
      });
    }

    await mongoose.disconnect();
    console.log('\n✅ Test complete');

  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  }
}

testDashboard();
