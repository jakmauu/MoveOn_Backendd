# 🚀 MoveOn Backend API

**Complete Node.js + Express + PostgreSQL backend for MoveOn Fitness Web Application**

Built with modern technologies and best practices, this backend provides a full-featured REST API for managing coaches, trainees, workout tasks, notifications, and more.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Database Setup](#-database-setup)
- [Running the Server](#-running-the-server)
- [API Documentation](#-api-documentation)
- [Testing](#-testing)
- [Deployment](#-deployment)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

- ✅ **JWT Authentication** - Secure token-based authentication
- ✅ **Role-Based Access Control** - Coach and trainee roles with permissions
- ✅ **RESTful API** - Clean, consistent API design
- ✅ **PostgreSQL Database** - Relational data with full ACID compliance
- ✅ **MongoDB Support** - Optional NoSQL for logging/analytics
- ✅ **Input Validation** - Comprehensive request validation
- ✅ **Error Handling** - Global error handling middleware
- ✅ **CORS Enabled** - Cross-origin resource sharing configured
- ✅ **Modular Architecture** - Clean separation of concerns
- ✅ **ESM Modules** - Modern ES6+ import/export syntax

---

## 🛠 Tech Stack

- **Runtime:** Node.js (v16+)
- **Framework:** Express.js
- **Database:** PostgreSQL (primary), MongoDB (optional)
- **Authentication:** JWT (jsonwebtoken)
- **Password Hashing:** bcrypt
- **Validation:** Custom validators
- **HTTP Client:** Axios (for external APIs)
- **Logging:** Morgan
- **Dev Tools:** Nodemon, Jest, Supertest

---

## 📁 Project Structure

```
moveon-backend/
│
├── server.js                    # Main application entry point
├── package.json                 # Dependencies and scripts
├── .env.example                 # Environment variables template
├── README.md                    # This file
│
├── database/
│   └── init.sql                 # PostgreSQL schema initialization
│
└── src/
    ├── config/                  # Configuration files
    │   ├── db_postgres.js       # PostgreSQL connection
    │   ├── db_mongo.js          # MongoDB connection (optional)
    │   └── jwt.js               # JWT configuration
    │
    ├── controllers/             # Business logic
    │   ├── auth.controller.js
    │   ├── coach.controller.js
    │   ├── task.controller.js
    │   ├── dashboard.controller.js
    │   ├── notification.controller.js
    │   └── template.controller.js
    │
    ├── models/                  # Database models
    │   ├── UserModel.js
    │   ├── CoachTraineeModel.js
    │   ├── TaskModel.js
    │   ├── TaskAssignmentModel.js
    │   ├── TraineeSubmissionModel.js
    │   ├── NotificationModel.js
    │   └── WorkoutTemplateModel.js
    │
    ├── routes/                  # API routes
    │   ├── auth.routes.js
    │   ├── coach.routes.js
    │   ├── task.routes.js
    │   ├── dashboard.routes.js
    │   ├── notification.routes.js
    │   └── template.routes.js
    │
    ├── middleware/              # Custom middleware
    │   ├── authMiddleware.js
    │   └── errorMiddleware.js
    │
    └── utils/                   # Utility functions
        ├── response.js
        └── validator.js
```

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v16 or higher) - [Download](https://nodejs.org/)
- **PostgreSQL** (v12 or higher) - [Download](https://www.postgresql.org/download/)
- **npm** or **yarn** - Comes with Node.js
- **Git** - [Download](https://git-scm.com/)

Optional:
- **MongoDB** (v5 or higher) - [Download](https://www.mongodb.com/try/download/community) (for logging)
- **Postman** or **Insomnia** - For API testing

---

## 🔧 Installation

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd "MoveOn - RPL"
```

### 2. Install dependencies

```bash
npm install
```

This will install all required packages listed in `package.json`.

---

## ⚙️ Configuration

### 1. Create `.env` file

Copy the example environment file:

```bash
cp .env.example .env
```

### 2. Configure environment variables

Edit `.env` with your settings:

```env
# Server Configuration
PORT=5000
NODE_ENV=development

# PostgreSQL Configuration
PG_HOST=localhost
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=your_password_here
PG_DATABASE=moveon

# MongoDB Configuration (optional)
MONGO_URI=mongodb://localhost:27017/moveon_logs

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production
JWT_EXPIRE=24h

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:3000
```

⚠️ **Important:** Change `JWT_SECRET` to a strong, random string in production!

---

## 💾 Database Setup

### Option 1: Using PostgreSQL Command Line

1. **Create database:**

```bash
psql -U postgres
CREATE DATABASE moveon;
\q
```

2. **Run initialization script:**

```bash
psql -U postgres -d moveon -f database/init.sql
```

### Option 2: Using pgAdmin

1. Open pgAdmin
2. Create a new database named `moveon`
3. Open Query Tool
4. Load and execute `database/init.sql`

### Verify Database Setup

```sql
-- Connect to database
\c moveon

-- List all tables
\dt

-- Check sample data
SELECT * FROM users;
SELECT * FROM workout_templates;
```

You should see:
- 7 tables created
- 4 sample users (1 coach, 3 trainees)
- 3 global workout templates

---

## 🚀 Running the Server

### Development Mode (with auto-reload)

```bash
npm run dev
```

### Production Mode

```bash
npm start
```

### Expected Output

```
🗄️  PostgreSQL connected successfully
🧩 MongoDB connected successfully

╔════════════════════════════════════════╗
║   🚀 MoveOn Backend Server Running   ║
╚════════════════════════════════════════╝

📡 Server:        http://localhost:5000
🌍 Environment:   development
🗄️  Database:      PostgreSQL
🔑 JWT Secret:    Configured

📚 API Documentation:
   - Root:         http://localhost:5000/
   - Health:       http://localhost:5000/health
   - Auth:         http://localhost:5000/api/auth
   - Coach:        http://localhost:5000/api/coach

✅ Server is ready to accept connections
```

---

## 📚 API Documentation

### Base URL

```
http://localhost:5000/api
```

### Authentication

All protected endpoints require a JWT token in the header:

```
Authorization: Bearer <your_jwt_token>
```

### Endpoints Overview

#### 🔐 Authentication (`/api/auth`)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/register` | Register new user | ❌ |
| POST | `/login` | Login user | ❌ |
| POST | `/logout` | Logout user | ✅ |
| GET | `/me` | Get current user | ✅ |

#### 👨‍🏫 Coach-Trainee Management (`/api/coach/:coachId`)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/trainees` | Get all trainees | ✅ Coach |
| GET | `/available-trainees` | Get available trainees | ✅ Coach |
| GET | `/trainee/:traineeId` | Get trainee detail | ✅ Coach |
| POST | `/add-trainee` | Add trainee to coach | ✅ Coach |
| DELETE | `/remove-trainee/:traineeId` | Remove trainee | ✅ Coach |

#### 📋 Tasks (`/api/coach/:coachId/tasks`)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/` | Get all tasks | ✅ Coach |
| POST | `/` | Create new task | ✅ Coach |
| GET | `/:taskId` | Get task detail | ✅ Coach |
| PUT | `/:taskId` | Update task | ✅ Coach |
| DELETE | `/:taskId` | Delete task | ✅ Coach |

#### 📊 Dashboard (`/api/coach/:coachId`)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/dashboard` | Get dashboard overview | ✅ Coach |
| GET | `/stats` | Get detailed statistics | ✅ Coach |

#### 🔔 Notifications (`/api/coach/:coachId/notifications`)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/` | Get all notifications | ✅ Coach |
| PATCH | `/:notificationId` | Mark as read | ✅ Coach |
| PATCH | `/mark-all-read` | Mark all as read | ✅ Coach |
| DELETE | `/:notificationId` | Delete notification | ✅ Coach |

#### 💪 Workout Templates (`/api/workout-templates`)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/` | Get global templates | ❌ |
| GET | `/:templateId` | Get template by ID | ❌ |
| POST | `/seed` | Seed default templates | ❌ |
| GET | `/coach/:coachId/workout-templates` | Get coach templates | ✅ Coach |
| POST | `/coach/:coachId/workout-templates` | Create custom template | ✅ Coach |

### Example Requests

#### 1. Register User

```bash
POST http://localhost:5000/api/auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123",
  "role": "coach",
  "avatar": "👨‍🏫"
}
```

#### 2. Login

```bash
POST http://localhost:5000/api/auth/login
Content-Type: application/json

{
  "email": "hendra@coach.com",
  "password": "password123"
}
```

Response:
```json
{
  "success": true,
  "message": "Login berhasil",
  "data": {
    "id": 1,
    "name": "Pak Hendra",
    "email": "hendra@coach.com",
    "role": "coach"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### 3. Get Trainees (Protected)

```bash
GET http://localhost:5000/api/coach/1/trainees
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## 🧪 Testing

### Run All Tests

```bash
npm test
```

### Test Individual Endpoints

Use Postman, Insomnia, or curl:

```bash
# Health check
curl http://localhost:5000/health

# Register user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@example.com","password":"password123","role":"trainee"}'
```

---

## 🌐 Deployment

### Heroku Deployment

1. **Install Heroku CLI**

```bash
npm install -g heroku
```

2. **Create Heroku app**

```bash
heroku create moveon-backend
```

3. **Add PostgreSQL addon**

```bash
heroku addons:create heroku-postgresql:mini
```

4. **Set environment variables**

```bash
heroku config:set JWT_SECRET=your_secret_here
heroku config:set NODE_ENV=production
```

5. **Deploy**

```bash
git push heroku main
```

6. **Run database migration**

```bash
heroku pg:psql < database/init.sql
```

### Railway/Render Deployment

Similar steps - connect GitHub repo and set environment variables in dashboard.

---

## 🐛 Troubleshooting

### Database Connection Error

**Problem:** `Error: connect ECONNREFUSED 127.0.0.1:5432`

**Solution:**
1. Check if PostgreSQL is running: `pg_isready`
2. Verify credentials in `.env`
3. Ensure database `moveon` exists

### Port Already in Use

**Problem:** `Error: listen EADDRINUSE: address already in use :::5000`

**Solution:**
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:5000 | xargs kill
```

Or change `PORT` in `.env` file.

### JWT Secret Warning

**Problem:** Using default JWT secret

**Solution:** Set strong `JWT_SECRET` in `.env`:
```bash
# Generate random secret
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Module Not Found

**Problem:** `Cannot find module 'express'`

**Solution:**
```bash
rm -rf node_modules package-lock.json
npm install
```

---

## 📝 API Response Format

### Success Response

```json
{
  "success": true,
  "message": "Operation successful",
  "data": { }
}
```

### Error Response

```json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE"
}
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

---

## 📄 License

This project is licensed under the MIT License.

---

## 👥 Support

For issues and questions:
- 📧 Email: support@moveon.com
- 💬 Discord: [Join Server](#)
- 📚 Documentation: [Full API Docs](BACKEND_REQUIREMENTS.md)

---

## ✅ Checklist for Production

- [ ] Change `JWT_SECRET` to strong random value
- [ ] Set `NODE_ENV=production`
- [ ] Enable HTTPS
- [ ] Set up database backups
- [ ] Configure rate limiting
- [ ] Set up monitoring (e.g., Sentry)
- [ ] Enable database connection pooling
- [ ] Set up CI/CD pipeline
- [ ] Configure proper CORS origins
- [ ] Add helmet.js for security headers

---

**Built with ❤️ by the MoveOn Team**

**Version:** 1.0.0  
**Last Updated:** October 28, 2025
