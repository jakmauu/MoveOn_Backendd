-- ============================================
-- MoveOn Backend - PostgreSQL Database Schema
-- ============================================
-- This script creates all necessary tables for the MoveOn fitness application
-- Run this script on a fresh PostgreSQL database

-- Create database (run separately if needed)
-- CREATE DATABASE moveon;
-- \c moveon;

-- ============================================
-- DROP EXISTING TABLES (if exists)
-- ============================================

DROP TABLE IF EXISTS trainee_submissions CASCADE;
DROP TABLE IF EXISTS task_assignments CASCADE;
DROP TABLE IF EXISTS tasks CASCADE;
DROP TABLE IF EXISTS notifications CASCADE;
DROP TABLE IF EXISTS workout_templates CASCADE;
DROP TABLE IF EXISTS coach_trainees CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ============================================
-- TABLE: users
-- ============================================

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(10) NOT NULL CHECK (role IN ('coach', 'trainee')),
  avatar VARCHAR(100),
  status VARCHAR(10) DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
  bio TEXT,
  phone VARCHAR(20),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for users table
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_status ON users(status);

-- ============================================
-- TABLE: coach_trainees
-- ============================================

CREATE TABLE coach_trainees (
  id SERIAL PRIMARY KEY,
  coach_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  trainee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('pending', 'accepted', 'active', 'inactive')),
  assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(coach_id, trainee_id)
);

-- Indexes for coach_trainees table
CREATE INDEX idx_coach_trainees_coach ON coach_trainees(coach_id);
CREATE INDEX idx_coach_trainees_trainee ON coach_trainees(trainee_id);

-- ============================================
-- TABLE: tasks
-- ============================================

CREATE TABLE tasks (
  id SERIAL PRIMARY KEY,
  coach_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(150) NOT NULL,
  description TEXT,
  exercises JSONB,
  difficulty VARCHAR(20) NOT NULL CHECK (difficulty IN ('Beginner', 'Intermediate', 'Advanced')),
  duration INTEGER,
  due_date DATE,
  status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'completed')),
  template_type VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for tasks table
CREATE INDEX idx_tasks_coach ON tasks(coach_id);
CREATE INDEX idx_tasks_difficulty ON tasks(difficulty);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_due_date ON tasks(due_date);

-- ============================================
-- TABLE: task_assignments
-- ============================================

CREATE TABLE task_assignments (
  id SERIAL PRIMARY KEY,
  task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  trainee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  coach_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(20) DEFAULT 'assigned' CHECK (status IN ('assigned', 'in_progress', 'completed', 'skipped')),
  assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  started_date TIMESTAMP,
  completed_date TIMESTAMP,
  notes TEXT
);

-- Indexes for task_assignments table
CREATE INDEX idx_task_assignments_trainee ON task_assignments(trainee_id);
CREATE INDEX idx_task_assignments_task ON task_assignments(task_id);
CREATE INDEX idx_task_assignments_coach ON task_assignments(coach_id);
CREATE INDEX idx_task_assignments_status ON task_assignments(status);

-- ============================================
-- TABLE: trainee_submissions
-- ============================================

CREATE TABLE trainee_submissions (
  id SERIAL PRIMARY KEY,
  assignment_id INTEGER NOT NULL REFERENCES task_assignments(id) ON DELETE CASCADE,
  trainee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  duration_actual INTEGER,
  calories_burned INTEGER,
  rating FLOAT CHECK (rating >= 0 AND rating <= 5),
  notes TEXT,
  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for trainee_submissions table
CREATE INDEX idx_trainee_submissions_assignment ON trainee_submissions(assignment_id);
CREATE INDEX idx_trainee_submissions_trainee ON trainee_submissions(trainee_id);

-- ============================================
-- TABLE: notifications
-- ============================================

CREATE TABLE notifications (
  id SERIAL PRIMARY KEY,
  coach_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  trainee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(20) DEFAULT 'completion' CHECK (type IN ('completion', 'upcoming', 'inactive', 'new_trainee')),
  title VARCHAR(100),
  message TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for notifications table
CREATE INDEX idx_notifications_coach ON notifications(coach_id);
CREATE INDEX idx_notifications_read ON notifications(is_read);
CREATE INDEX idx_notifications_created ON notifications(created_at);

-- ============================================
-- TABLE: workout_templates
-- ============================================

CREATE TABLE workout_templates (
  id SERIAL PRIMARY KEY,
  coach_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  icon VARCHAR(50),
  description TEXT,
  duration INTEGER,
  exercises JSONB,
  difficulty VARCHAR(20) CHECK (difficulty IN ('Beginner', 'Intermediate', 'Advanced')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for workout_templates table
CREATE INDEX idx_workout_templates_coach ON workout_templates(coach_id);
CREATE INDEX idx_workout_templates_difficulty ON workout_templates(difficulty);

-- ============================================
-- TRIGGER: Update updated_at timestamp
-- ============================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = CURRENT_TIMESTAMP;
   RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tasks_updated_at BEFORE UPDATE ON tasks
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- SEED DATA (Sample)
-- ============================================

-- Sample Coach User (password: password123)
INSERT INTO users (name, email, password, role, avatar, status, bio, phone) VALUES
('Pak Hendra', 'hendra@coach.com', '$2b$10$YourHashedPasswordHere', 'coach', NULL, 'active', 'Professional Personal Trainer', '+6281234567890');

-- Sample Trainee Users (password: password123)
INSERT INTO users (name, email, password, role, avatar, status) VALUES
('Budi Santoso', 'budi@trainee.com', '$2b$10$YourHashedPasswordHere', 'trainee', NULL, 'active'),
('Siti Nuraini', 'siti@trainee.com', '$2b$10$YourHashedPasswordHere', 'trainee', NULL, 'active'),
('Ahmad Rizki', 'ahmad@trainee.com', '$2b$10$YourHashedPasswordHere', 'trainee', NULL, 'active');

-- Sample Global Workout Templates
INSERT INTO workout_templates (coach_id, name, icon, description, duration, exercises, difficulty) VALUES
(NULL, 'Strength Training', 'strength', 'Build muscle strength and power', 60, 
 '[{"name":"Push ups","sets":3,"reps":15,"duration":10,"intensity":"medium"},{"name":"Pull ups","sets":3,"reps":10,"duration":10,"intensity":"high"},{"name":"Squats","sets":4,"reps":12,"duration":12,"intensity":"medium"}]'::jsonb,
 'Intermediate'),
(NULL, 'Cardio Blast', 'cardio', 'High intensity cardio workout', 45,
 '[{"name":"Running","sets":1,"reps":0,"duration":20,"intensity":"high"},{"name":"Burpees","sets":3,"reps":15,"duration":10,"intensity":"high"}]'::jsonb,
 'Advanced'),
(NULL, 'Yoga Flow', 'yoga', 'Relaxing yoga and stretching', 30,
 '[{"name":"Sun salutation","sets":3,"reps":5,"duration":15,"intensity":"low"},{"name":"Warrior pose","sets":2,"reps":0,"duration":5,"intensity":"low"}]'::jsonb,
 'Beginner');

-- ============================================
-- VERIFICATION QUERIES
-- ============================================

-- Check table creation
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
ORDER BY table_name;

-- Check row counts
SELECT 
  (SELECT COUNT(*) FROM users) as users_count,
  (SELECT COUNT(*) FROM coach_trainees) as coach_trainees_count,
  (SELECT COUNT(*) FROM tasks) as tasks_count,
  (SELECT COUNT(*) FROM task_assignments) as task_assignments_count,
  (SELECT COUNT(*) FROM trainee_submissions) as trainee_submissions_count,
  (SELECT COUNT(*) FROM notifications) as notifications_count,
  (SELECT COUNT(*) FROM workout_templates) as workout_templates_count;

-- ============================================
-- DATABASE SETUP COMPLETE
-- ============================================

COMMIT;

-- Print success message
\echo ''
\echo '✅ Database schema created successfully!'
\echo '✅ Sample data inserted!'
\echo ''
\echo '📝 Next steps:'
\echo '   1. Update .env file with your database credentials'
\echo '   2. Run: npm install'
\echo '   3. Run: npm run dev'
\echo ''
