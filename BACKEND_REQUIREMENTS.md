# 🔧 Backend Requirements untuk MoveOn

## 📌 Overview

Dokumentasi ini berisi **semua backend requirements** yang harus dibuat agar frontend yang sudah jadi bisa terhubung dengan lancar dan baik. Didasarkan pada frontend coach features yang sudah dikembangkan.

**Backend Stack Recommended:**
- Node.js + Express.js
- MySQL / PostgreSQL
- JWT Authentication
- RESTful API

---

## 🗂️ Database Schema

### **1️⃣ Tabel: users**
**Purpose:** Menyimpan data user (coach dan trainee)

```sql
CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL (hashed with bcrypt),
  role ENUM('coach', 'trainee') NOT NULL,
  avatar VARCHAR(100), -- emoji atau URL
  status ENUM('active', 'inactive') DEFAULT 'active',
  bio TEXT,
  phone VARCHAR(20),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_role (role)
);
```

**Contoh Data:**
```sql
INSERT INTO users VALUES 
(1, 'Pak Hendra', 'hendra@coach.com', '$2b$10...', 'coach', '👨‍🏫', 'active', 'Personal Trainer', '+6281234567890', NOW(), NOW()),
(2, 'Budi Santoso', 'budi@trainee.com', '$2b$10...', 'trainee', '👨', 'active', 'Software Engineer', '+6281234567891', NOW(), NOW()),
(3, 'Siti Nuraini', 'siti@trainee.com', '$2b$10...', 'trainee', '👩', 'active', NULL, NULL, NOW(), NOW());
```

---

### **2️⃣ Tabel: coach_trainees**
**Purpose:** Relationship antara coach dan trainee (Many-to-Many)

```sql
CREATE TABLE coach_trainees (
  id INT PRIMARY KEY AUTO_INCREMENT,
  coach_id INT NOT NULL,
  trainee_id INT NOT NULL,
  status ENUM('pending', 'accepted', 'active', 'inactive') DEFAULT 'active',
  assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (trainee_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY unique_coach_trainee (coach_id, trainee_id),
  INDEX idx_coach (coach_id),
  INDEX idx_trainee (trainee_id)
);
```

**Catatan:** 
- 1 Coach bisa punya banyak Trainee
- 1 Trainee bisa punya banyak Coach
- `status` bisa untuk request/accept flow di masa depan

---

### **3️⃣ Tabel: tasks**
**Purpose:** Menyimpan semua workout tasks yang dibuat coach

```sql
CREATE TABLE tasks (
  id INT PRIMARY KEY AUTO_INCREMENT,
  coach_id INT NOT NULL,
  title VARCHAR(150) NOT NULL,
  description TEXT,
  exercises JSON, -- [{name, sets, reps, duration, intensity}, ...]
  difficulty ENUM('Beginner', 'Intermediate', 'Advanced') NOT NULL,
  duration INT, -- dalam menit (e.g. 60)
  due_date DATE,
  status ENUM('draft', 'published', 'completed') DEFAULT 'draft',
  template_type VARCHAR(50), -- 'strength', 'cardio', 'hiit', 'flexibility', 'core'
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_coach (coach_id),
  INDEX idx_difficulty (difficulty),
  INDEX idx_status (status)
);
```

**Contoh Data:**
```sql
INSERT INTO tasks VALUES 
(1, 1, 'Upper Body Strength', 'Focus on chest and back', 
 '[{"name":"Push ups","sets":3,"reps":15,"duration":10,"intensity":"medium"},...]',
 'Intermediate', 60, '2024-11-10', 'published', 'strength', NOW(), NOW()),
(2, 1, 'Cardio & Conditioning', 'Running + cycling combo',
 '[{"name":"Running","sets":1,"reps":0,"duration":30,"intensity":"high"},...]',
 'Intermediate', 45, '2024-11-12', 'published', 'cardio', NOW(), NOW());
```

---

### **4️⃣ Tabel: task_assignments**
**Purpose:** Menyimpan assign task ke trainee

```sql
CREATE TABLE task_assignments (
  id INT PRIMARY KEY AUTO_INCREMENT,
  task_id INT NOT NULL,
  trainee_id INT NOT NULL,
  coach_id INT NOT NULL,
  status ENUM('assigned', 'in_progress', 'completed', 'skipped') DEFAULT 'assigned',
  assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  started_date TIMESTAMP NULL,
  completed_date TIMESTAMP NULL,
  notes TEXT,
  FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
  FOREIGN KEY (trainee_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_trainee (trainee_id),
  INDEX idx_task (task_id),
  INDEX idx_status (status)
);
```

---

### **5️⃣ Tabel: trainee_submissions**
**Purpose:** Menyimpan data completion dari trainee (untuk tracking progress)

```sql
CREATE TABLE trainee_submissions (
  id INT PRIMARY KEY AUTO_INCREMENT,
  assignment_id INT NOT NULL,
  trainee_id INT NOT NULL,
  duration_actual INT, -- actual duration in minutes
  calories_burned INT,
  rating FLOAT, -- 1-5 star rating dari coach
  notes TEXT,
  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (assignment_id) REFERENCES task_assignments(id) ON DELETE CASCADE,
  FOREIGN KEY (trainee_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_assignment (assignment_id),
  INDEX idx_trainee (trainee_id)
);
```

---

### **6️⃣ Tabel: notifications**
**Purpose:** Menyimpan notifikasi untuk coach

```sql
CREATE TABLE notifications (
  id INT PRIMARY KEY AUTO_INCREMENT,
  coach_id INT NOT NULL,
  trainee_id INT NOT NULL,
  type ENUM('completion', 'upcoming', 'inactive', 'new_trainee') DEFAULT 'completion',
  title VARCHAR(100),
  message TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (trainee_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_coach (coach_id),
  INDEX idx_read (is_read)
);
```

**Tipe Notifikasi:**
- `completion` - Trainee menyelesaikan task
- `upcoming` - Task deadline mau datang
- `inactive` - Trainee inactive lama
- `new_trainee` - Trainee baru di-add

---

### **7️⃣ Tabel: workout_templates**
**Purpose:** Template workout untuk quick task creation

```sql
CREATE TABLE workout_templates (
  id INT PRIMARY KEY AUTO_INCREMENT,
  coach_id INT, -- NULL untuk global templates
  name VARCHAR(100) NOT NULL,
  icon VARCHAR(50), -- emoji
  description TEXT,
  duration INT, -- minutes
  exercises JSON,
  difficulty ENUM('Beginner', 'Intermediate', 'Advanced'),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_coach (coach_id)
);
```

---

## 🔌 API Endpoints

### **Authentication Endpoints**

#### **POST /api/auth/register**
Register user baru (coach atau trainee)

**Request:**
```json
{
  "name": "Budi Santoso",
  "email": "budi@example.com",
  "password": "password123",
  "role": "trainee", // or "coach"
  "avatar": "👨"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Registrasi berhasil",
  "data": {
    "id": 2,
    "name": "Budi Santoso",
    "email": "budi@example.com",
    "role": "trainee"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

#### **POST /api/auth/login**
Login user

**Request:**
```json
{
  "email": "budi@example.com",
  "password": "password123"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Login berhasil",
  "data": {
    "id": 2,
    "name": "Budi Santoso",
    "email": "budi@example.com",
    "role": "trainee",
    "status": "active"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

#### **POST /api/auth/logout**
Logout user (optional, token-based auth)

**Response (200):**
```json
{
  "success": true,
  "message": "Logout berhasil"
}
```

---

### **Coach Trainees Management**

#### **GET /api/coach/:coachId/trainees**
Get semua trainee yang sudah di-add coach

**Query Params:**
- `status` - active/inactive/all
- `search` - cari by name/email
- `sort` - streak/workouts/hours

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": 2,
      "name": "Budi Santoso",
      "email": "budi@example.com",
      "avatar": "👨",
      "status": "active",
      "connectedSince": "2024-09-15T08:00:00Z",
      "stats": {
        "workoutsCompleted": 12,
        "totalHours": 24,
        "caloriesBurned": 5200,
        "averageRating": 4.5,
        "streak": 5
      }
    }
  ],
  "count": 1
}
```

---

#### **GET /api/coach/:coachId/available-trainees**
Get trainee yang belum di-add (untuk add trainee page)

**Query Params:**
- `search` - cari by name/email

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": 5,
      "name": "Adi Pratama",
      "email": "adi@example.com",
      "avatar": "👨",
      "status": "active",
      "experience": "Intermediate",
      "createdAt": "2024-10-20T10:00:00Z"
    }
  ],
  "count": 8
}
```

---

#### **GET /api/coach/:coachId/trainee/:traineeId**
Get detail satu trainee (untuk trainee detail page)

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": 2,
    "name": "Budi Santoso",
    "email": "budi@example.com",
    "avatar": "👨",
    "status": "active",
    "joinDate": "2024-09-15T08:00:00Z",
    "stats": {
      "workoutsCompleted": 12,
      "totalHours": 24,
      "caloriesBurned": 5200,
      "averageRating": 4.5,
      "streak": 5
    },
    "progressMetrics": {
      "completionRate": 85,
      "consistencyScore": 90,
      "qualityScore": 88
    },
    "recentActivities": [
      {
        "id": 1,
        "date": "2024-10-28",
        "workoutName": "Cardio Session",
        "duration": 45,
        "calories": 450
      }
    ],
    "assignedTasks": [
      {
        "id": 1,
        "title": "Upper Body Strength",
        "difficulty": "Intermediate",
        "dueDate": "2024-11-10",
        "exerciseCount": 4,
        "status": "in_progress"
      }
    ]
  }
}
```

---

#### **POST /api/coach/:coachId/add-trainee**
Add trainee ke coach

**Request:**
```json
{
  "traineeId": 5
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Trainee berhasil ditambahkan",
  "data": {
    "coachTraineeId": 15,
    "coachId": 1,
    "traineeId": 5,
    "status": "active",
    "assignedDate": "2024-10-28T10:30:00Z"
  }
}
```

---

#### **DELETE /api/coach/:coachId/remove-trainee/:traineeId**
Remove trainee dari coach

**Response (200):**
```json
{
  "success": true,
  "message": "Trainee berhasil dihapus",
  "data": {
    "removed": true,
    "traineeId": 5
  }
}
```

---

### **Tasks Management**

#### **GET /api/coach/:coachId/tasks**
Get semua task yang dibuat coach

**Query Params:**
- `difficulty` - Beginner/Intermediate/Advanced/all
- `status` - draft/published/completed/all
- `search` - cari by title
- `sort` - recent/dueDate/difficulty

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "title": "Upper Body Strength",
      "description": "Focus on chest and back",
      "difficulty": "Intermediate",
      "duration": 60,
      "dueDate": "2024-11-10",
      "status": "published",
      "exercises": [
        {
          "name": "Push ups",
          "sets": 3,
          "reps": 15,
          "duration": 10,
          "intensity": "medium"
        }
      ],
      "assignedTo": [
        {
          "traineeId": 2,
          "traineeName": "Budi Santoso",
          "status": "completed"
        }
      ],
      "createdAt": "2024-10-25T08:00:00Z"
    }
  ],
  "count": 4
}
```

---

#### **POST /api/coach/:coachId/tasks**
Create task baru (dari assign task wizard step 1-3)

**Request:**
```json
{
  "title": "Upper Body Strength",
  "description": "Focus on chest and back",
  "difficulty": "Intermediate",
  "duration": 60,
  "dueDate": "2024-11-10",
  "templateType": "strength",
  "exercises": [
    {
      "name": "Push ups",
      "sets": 3,
      "reps": 15,
      "duration": 10,
      "intensity": "medium"
    }
  ],
  "trainees": [2, 3] // trainee IDs untuk assign
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Task berhasil dibuat",
  "data": {
    "id": 1,
    "coachId": 1,
    "title": "Upper Body Strength",
    "createdAt": "2024-10-28T10:30:00Z",
    "assignmentIds": [5, 6]
  }
}
```

---

#### **GET /api/coach/:coachId/tasks/:taskId**
Get detail task

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "title": "Upper Body Strength",
    "description": "Focus on chest and back",
    "difficulty": "Intermediate",
    "duration": 60,
    "dueDate": "2024-11-10",
    "exercises": [...],
    "assignedTrainees": [
      {
        "traineeId": 2,
        "traineeName": "Budi Santoso",
        "status": "completed",
        "submittedAt": "2024-10-27T18:00:00Z",
        "caloriesBurned": 450
      }
    ]
  }
}
```

---

#### **PUT /api/coach/:coachId/tasks/:taskId**
Update task

**Request:**
```json
{
  "title": "Upper Body Strength (Updated)",
  "description": "New description",
  "difficulty": "Advanced",
  "duration": 90
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Task berhasil diupdate",
  "data": { /* updated task */ }
}
```

---

#### **DELETE /api/coach/:coachId/tasks/:taskId**
Delete task

**Response (200):**
```json
{
  "success": true,
  "message": "Task berhasil dihapus",
  "data": {
    "deletedId": 1,
    "assignmentsCancelled": 3
  }
}
```

---

### **Dashboard / Statistics**

#### **GET /api/coach/:coachId/dashboard**
Get dashboard overview data

**Response (200):**
```json
{
  "success": true,
  "data": {
    "stats": {
      "totalTrainees": 4,
      "activeTasks": 3,
      "totalHours": 96,
      "notifications": 2
    },
    "recentNotifications": [
      {
        "id": 1,
        "type": "completion",
        "traineeName": "Budi Santoso",
        "message": "Menyelesaikan Upper Body Strength",
        "timestamp": "2024-10-28T18:00:00Z",
        "isRead": false
      }
    ],
    "traineesOverview": [
      {
        "id": 2,
        "name": "Budi Santoso",
        "avatar": "👨",
        "status": "active",
        "stats": {
          "workoutsCompleted": 12,
          "streak": 5,
          "averageRating": 4.5
        }
      }
    ]
  }
}
```

---

### **Notifications**

#### **GET /api/coach/:coachId/notifications**
Get all notifications

**Query Params:**
- `unreadOnly` - true/false
- `limit` - jumlah hasil (default 20)

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "type": "completion",
      "traineeName": "Budi Santoso",
      "message": "Menyelesaikan Upper Body Strength",
      "timestamp": "2024-10-28T18:00:00Z",
      "isRead": false
    }
  ],
  "unreadCount": 2
}
```

---

#### **PATCH /api/coach/:coachId/notifications/:notificationId**
Mark notification as read

**Response (200):**
```json
{
  "success": true,
  "message": "Notifikasi marked as read",
  "data": { /* updated notification */ }
}
```

---

#### **PATCH /api/coach/:coachId/notifications/mark-all-read**
Mark semua notifikasi as read

**Response (200):**
```json
{
  "success": true,
  "message": "Semua notifikasi marked as read"
}
```

---

### **Workout Templates**

#### **GET /api/workout-templates**
Get global workout templates

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "Strength Training",
      "icon": "💪",
      "description": "Build muscle strength",
      "duration": 60,
      "difficulty": "Intermediate",
      "exercises": [
        {
          "name": "Push ups",
          "sets": 3,
          "reps": 15,
          "duration": 10,
          "intensity": "medium"
        }
      ]
    }
  ]
}
```

---

#### **GET /api/coach/:coachId/workout-templates**
Get coach's custom templates + global templates

**Response (200):** (same structure)

---

## 🔐 Authentication & Security

### **JWT Token Implementation**
```javascript
// Token payload structure
{
  "id": 1,
  "email": "coach@example.com",
  "role": "coach",
  "iat": 1698545760,
  "exp": 1698632160 // 24 hours
}
```

### **Headers Requirement**
Semua request (kecuali login/register) harus include:
```
Authorization: Bearer <token>
Content-Type: application/json
```

### **Middleware to Implement**
```javascript
// auth middleware
authenticateToken(req, res, next) // verify JWT

// role middleware
authorizeCoach(req, res, next) // verify role === 'coach'

// ownership middleware
verifyCoachOwnership(req, res, next) // verify coach_id match
```

---

## 📊 Data Flow Diagram

```
┌─────────────────┐
│   Frontend      │
│  (React/Vite)   │
└────────┬────────┘
         │
         │ HTTP Requests
         │ (REST API)
         │
┌────────▼────────┐
│  Backend Server │
│ (Express.js)    │
└────────┬────────┘
         │
         │ SQL Queries
         │
┌────────▼────────┐
│   Database      │
│ (MySQL/Postgres)│
└─────────────────┘
```

### **Request Flow Example (Create Task):**
```
1. Frontend: POST /api/coach/1/tasks
   └─ Validate form
   └─ Check auth token
   └─ Send request

2. Backend: Receive request
   └─ Verify JWT token
   └─ Verify coach ownership
   └─ Validate data
   └─ Create task record
   └─ Create task_assignments for selected trainees
   └─ Generate notifications for trainees
   └─ Return response

3. Frontend: Receive response
   └─ Update state
   └─ Show success message
   └─ Redirect to task list
```

---

## 🚀 Development Checklist

### **Phase 1: Setup & Authentication**
- [ ] Setup Node.js + Express.js project
- [ ] Setup MySQL database
- [ ] Create database tables (schema)
- [ ] Setup JWT authentication
- [ ] Implement POST /auth/register
- [ ] Implement POST /auth/login
- [ ] Setup auth middleware

### **Phase 2: Coach Trainees**
- [ ] Implement GET /coach/:coachId/trainees
- [ ] Implement GET /coach/:coachId/available-trainees
- [ ] Implement GET /coach/:coachId/trainee/:traineeId
- [ ] Implement POST /coach/:coachId/add-trainee
- [ ] Implement DELETE /coach/:coachId/remove-trainee/:traineeId

### **Phase 3: Tasks Management**
- [ ] Implement GET /coach/:coachId/tasks
- [ ] Implement POST /coach/:coachId/tasks (create + assign)
- [ ] Implement GET /coach/:coachId/tasks/:taskId
- [ ] Implement PUT /coach/:coachId/tasks/:taskId
- [ ] Implement DELETE /coach/:coachId/tasks/:taskId
- [ ] Setup task_assignments creation on POST tasks

### **Phase 4: Dashboard & Notifications**
- [ ] Implement GET /coach/:coachId/dashboard
- [ ] Implement GET /coach/:coachId/notifications
- [ ] Implement PATCH /coach/:coachId/notifications/:notificationId
- [ ] Setup notification triggers (task completion, upcoming, etc)

### **Phase 5: Templates & Utilities**
- [ ] Implement GET /workout-templates
- [ ] Implement GET /coach/:coachId/workout-templates
- [ ] Setup email notifications (optional)
- [ ] Setup logging & error handling

### **Phase 6: Testing & Deployment**
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Test all endpoints dengan Postman/Insomnia
- [ ] Setup CORS for frontend
- [ ] Deploy to production

---

## 💾 Database Initialization Script

```sql
-- Create database
CREATE DATABASE moveon;
USE moveon;

-- Users table
CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role ENUM('coach', 'trainee') NOT NULL,
  avatar VARCHAR(100),
  status ENUM('active', 'inactive') DEFAULT 'active',
  bio TEXT,
  phone VARCHAR(20),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_role (role)
);

-- Coach-Trainees table
CREATE TABLE coach_trainees (
  id INT PRIMARY KEY AUTO_INCREMENT,
  coach_id INT NOT NULL,
  trainee_id INT NOT NULL,
  status ENUM('pending', 'accepted', 'active', 'inactive') DEFAULT 'active',
  assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (trainee_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY unique_coach_trainee (coach_id, trainee_id),
  INDEX idx_coach (coach_id),
  INDEX idx_trainee (trainee_id)
);

-- Tasks table
CREATE TABLE tasks (
  id INT PRIMARY KEY AUTO_INCREMENT,
  coach_id INT NOT NULL,
  title VARCHAR(150) NOT NULL,
  description TEXT,
  exercises JSON,
  difficulty ENUM('Beginner', 'Intermediate', 'Advanced') NOT NULL,
  duration INT,
  due_date DATE,
  status ENUM('draft', 'published', 'completed') DEFAULT 'draft',
  template_type VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_coach (coach_id),
  INDEX idx_difficulty (difficulty),
  INDEX idx_status (status)
);

-- Task Assignments table
CREATE TABLE task_assignments (
  id INT PRIMARY KEY AUTO_INCREMENT,
  task_id INT NOT NULL,
  trainee_id INT NOT NULL,
  coach_id INT NOT NULL,
  status ENUM('assigned', 'in_progress', 'completed', 'skipped') DEFAULT 'assigned',
  assigned_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  started_date TIMESTAMP NULL,
  completed_date TIMESTAMP NULL,
  notes TEXT,
  FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
  FOREIGN KEY (trainee_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_trainee (trainee_id),
  INDEX idx_task (task_id),
  INDEX idx_status (status)
);

-- Trainee Submissions table
CREATE TABLE trainee_submissions (
  id INT PRIMARY KEY AUTO_INCREMENT,
  assignment_id INT NOT NULL,
  trainee_id INT NOT NULL,
  duration_actual INT,
  calories_burned INT,
  rating FLOAT,
  notes TEXT,
  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (assignment_id) REFERENCES task_assignments(id) ON DELETE CASCADE,
  FOREIGN KEY (trainee_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_assignment (assignment_id),
  INDEX idx_trainee (trainee_id)
);

-- Notifications table
CREATE TABLE notifications (
  id INT PRIMARY KEY AUTO_INCREMENT,
  coach_id INT NOT NULL,
  trainee_id INT NOT NULL,
  type ENUM('completion', 'upcoming', 'inactive', 'new_trainee') DEFAULT 'completion',
  title VARCHAR(100),
  message TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (trainee_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_coach (coach_id),
  INDEX idx_read (is_read)
);

-- Workout Templates table
CREATE TABLE workout_templates (
  id INT PRIMARY KEY AUTO_INCREMENT,
  coach_id INT,
  name VARCHAR(100) NOT NULL,
  icon VARCHAR(50),
  description TEXT,
  duration INT,
  exercises JSON,
  difficulty ENUM('Beginner', 'Intermediate', 'Advanced'),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (coach_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_coach (coach_id)
);
```

---

## 🔗 Frontend-Backend Integration Points

### **1. Login & Auth**
```javascript
// Frontend call
const response = await axios.post('/api/auth/login', {
  email: 'coach@example.com',
  password: 'password123'
})
// Save token ke localStorage
localStorage.setItem('token', response.data.token)
```

### **2. Set Default Header**
```javascript
// Setup axios interceptor
axios.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})
```

### **3. Fetch Trainees**
```javascript
// Frontend: CoachTraineesPage.jsx
const response = await axios.get(`/api/coach/${coachId}/trainees`)
setTrainees(response.data.data)
```

### **4. Create Task**
```javascript
// Frontend: CoachAssignTask.jsx step 4 submit
const response = await axios.post(
  `/api/coach/${coachId}/tasks`,
  {
    title, description, difficulty, duration, dueDate,
    exercises, trainees: selectedTraineeIds
  }
)
```

---

## 📝 Error Handling

### **Standard Error Response Format:**
```json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE"
}
```

### **HTTP Status Codes to Use:**
- `200` - OK
- `201` - Created
- `400` - Bad Request (validation error)
- `401` - Unauthorized (invalid token)
- `403` - Forbidden (no permission)
- `404` - Not Found
- `500` - Server Error

---

## 🧪 Testing with Postman/Insomnia

### **Collection Structure:**
```
MoveOn API
├── Authentication
│   ├── POST /auth/register
│   ├── POST /auth/login
│   └── POST /auth/logout
├── Coach - Trainees
│   ├── GET /coach/:coachId/trainees
│   ├── GET /coach/:coachId/available-trainees
│   ├── GET /coach/:coachId/trainee/:traineeId
│   ├── POST /coach/:coachId/add-trainee
│   └── DELETE /coach/:coachId/remove-trainee/:traineeId
├── Coach - Tasks
│   ├── GET /coach/:coachId/tasks
│   ├── POST /coach/:coachId/tasks
│   ├── GET /coach/:coachId/tasks/:taskId
│   ├── PUT /coach/:coachId/tasks/:taskId
│   └── DELETE /coach/:coachId/tasks/:taskId
├── Dashboard
│   └── GET /coach/:coachId/dashboard
├── Notifications
│   ├── GET /coach/:coachId/notifications
│   ├── PATCH /coach/:coachId/notifications/:notificationId
│   └── PATCH /coach/:coachId/notifications/mark-all-read
└── Templates
    ├── GET /workout-templates
    └── GET /coach/:coachId/workout-templates
```

---

## 📋 Summary

| Komponen | Jumlah | Status |
|----------|--------|--------|
| **Database Tables** | 7 | ✅ Defined |
| **API Endpoints** | 18 | ✅ Specified |
| **Authentication** | JWT Token | ✅ Required |
| **Frontend Integration** | Full | ✅ Ready |
| **Error Handling** | Standard | ✅ Defined |
| **Testing** | Postman ready | ✅ Testable |

---

## 🎯 Next Steps

1. **Setup Backend Project**
   - Initialize Node.js + Express.js
   - Install dependencies (express, mysql2, jsonwebtoken, bcrypt, cors)

2. **Create Database**
   - Run SQL script untuk create tables
   - Test database connection

3. **Implement Authentication**
   - Setup JWT configuration
   - Create auth middleware
   - Implement register & login endpoints

4. **Implement Core Features**
   - Follow development checklist di atas
   - Test setiap endpoint dengan Postman

5. **Integration Testing**
   - Connect frontend dengan backend
   - Test full flow dari login hingga create task

6. **Deployment**
   - Deploy backend ke server
   - Update frontend API base URL

---

**Backend Requirements v1.0**  
**Last Updated:** 28 Oktober 2024  
**Status:** ✅ Ready for Development  

Semua yang dibutuhkan untuk backend sudah terdokumentasi! 🚀
