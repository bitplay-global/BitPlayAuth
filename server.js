const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/database');
const errorHandler = require('./middleware/errorHandler');

// Load env vars
dotenv.config();

// Connect to database
connectDB();

const app = express();

// Behind nginx on the same machine: take the client IP from X-Forwarded-For
// (nginx sets it), otherwise every user shares 127.0.0.1 and one rate-limit
// bucket.
app.set('trust proxy', 'loopback');

// Security middleware
app.use(helmet());

// CORS - Allow all origins for mobile app
app.use(cors({
  origin: true, // Allow all origins for mobile app
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  }
});

app.use(limiter);

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Refuse MongoDB operators smuggled into queries, e.g. a login body
// {"email": {"$ne": null}} or ?email[$regex]=^a.
app.use(require('./middleware/noOperatorInjection'));

// Tighter limits on the endpoints that check secrets or send email.
const strictLimiter = (max) => rateLimit({
  windowMs: 15 * 60 * 1000,
  max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many attempts. Please wait a few minutes and try again.' }
});
app.use(['/api/auth/login', '/api/auth/social-login'], strictLimiter(30));
app.use(['/api/auth/forgotpassword', '/api/auth/resend-verification', '/api/auth/update-email-otp', '/api/auth/two-factor-otp'], strictLimiter(10));
app.use(['/api/auth/verify-email-otp', '/api/auth/verify-twofactorotp', '/api/auth/update-email', '/api/auth/resetpassword', '/api/auth/register'], strictLimiter(20));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/admin', require('./routes/admin'));

// Health check route
app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV
  });
});

// Handle 404 routes
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Error handler middleware (should be last)
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

// Only reachable through nginx on this machine (HTTPS, real client IP,
// blocklist). It used to listen on every interface, so http://<ip>:5000
// bypassed all of that. Set HOST=0.0.0.0 only if that is really wanted.
const HOST = process.env.HOST || "127.0.0.1";

const server = app.listen(PORT, HOST, () => {
  console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  console.log(`Error: ${err.message}`);
  // Close server & exit process
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.log(`Error: ${err.message}`);
  console.log('Shutting down the server due to uncaught exception');
  process.exit(1);
});

module.exports = app;
