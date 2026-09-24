# Authentication Backend API

A Node.js backend with MongoDB for user authentication including registration, login, and forgot password functionality.

## Features

- User Registration
- User Login
- Forgot Password with Email Reset
- JWT Authentication
- Password Hashing with bcrypt
- Rate Limiting
- Input Validation
- Error Handling
- CORS Support
- Security Headers

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (local or cloud)
- Email service (Gmail recommended)

## Installation

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables:
Copy `.env` file and update the following variables:
- `MONGODB_URI`: Your MongoDB connection string
- `JWT_SECRET`: A secure secret key for JWT tokens
- `EMAIL_USER`: Your email address for sending reset emails
- `EMAIL_PASS`: Your email app password

3. Start the server:
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## API Endpoints

### Authentication Routes

#### Register User
- **POST** `/api/auth/register`
- **Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
```
- **Response:**
```json
{
  "success": true,
  "token": "jwt_token_here",
  "user": {
    "id": "user_id",
    "name": "John Doe",
    "email": "john@example.com",
    "isActive": true,
    "createdAt": "2023-01-01T00:00:00.000Z"
  }
}
```

#### Login User
- **POST** `/api/auth/login`
- **Body:**
```json
{
  "email": "john@example.com",
  "password": "password123"
}
```
- **Response:** Same as register

#### Get Current User
- **GET** `/api/auth/me`
- **Headers:** `Authorization: Bearer <token>`
- **Response:**
```json
{
  "success": true,
  "user": {
    "id": "user_id",
    "name": "John Doe",
    "email": "john@example.com",
    "isActive": true,
    "lastLogin": "2023-01-01T00:00:00.000Z",
    "createdAt": "2023-01-01T00:00:00.000Z"
  }
}
```

#### Forgot Password
- **POST** `/api/auth/forgotpassword`
- **Body:**
```json
{
  "email": "john@example.com"
}
```
- **Response:**
```json
{
  "success": true,
  "message": "Email sent successfully"
}
```

#### Reset Password
- **PUT** `/api/auth/resetpassword/:resettoken`
- **Body:**
```json
{
  "password": "newpassword123"
}
```
- **Response:** Same as login

#### Logout
- **GET** `/api/auth/logout`
- **Headers:** `Authorization: Bearer <token>`
- **Response:**
```json
{
  "success": true,
  "message": "User logged out successfully"
}
```

### Health Check
- **GET** `/api/health`
- **Response:**
```json
{
  "success": true,
  "message": "Server is running",
  "timestamp": "2023-01-01T00:00:00.000Z",
  "environment": "development"
}
```

## Error Responses

All error responses follow this format:
```json
{
  "success": false,
  "message": "Error description"
}
```

Common HTTP status codes:
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (invalid credentials/token)
- `404`: Not Found (user/route not found)
- `429`: Too Many Requests (rate limit exceeded)
- `500`: Internal Server Error

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Rate limiting (100 requests per 15 minutes)
- CORS protection
- Security headers with Helmet
- Input validation
- SQL injection protection with Mongoose

## Environment Variables

```env
PORT=5000
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/auth_demo
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRE=7d
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
EMAIL_FROM=noreply@authdemo.com
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

## Testing

You can test the API using tools like Postman, curl, or any HTTP client.

Example curl commands:

```bash
# Register
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com","password":"password123"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password":"password123"}'

# Get current user (replace TOKEN with actual token)
curl -X GET http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer TOKEN"
```
