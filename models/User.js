const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Generate unique referral code
const generateReferralCode = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please provide a name'],
    trim: true,
    maxlength: [50, 'Name cannot be more than 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Please provide an email'],
    unique: true,
    lowercase: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      'Please provide a valid email'
    ]
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  photo: {
    type: String,
    default: null
  },
  gender: {
    type: String,
    enum: ['Male', 'Female', 'Other', 'Prefer not to say', null],
    default: null
  },
  phoneNumber: {
    type: String,
    default: null,
    trim: true
  },
  country: {
    type: String,
    default: null,
    trim: true
  },
  city: {
    type: String,
    default: null,
    trim: true
  },
  socialProviders: {
    google: {
      id: String,
      accessToken: String
    },
    apple: {
      id: String,
      accessToken: String
    },
    facebook: {
      id: String,
      accessToken: String
    },
    linkedin: {
      id: String,
      accessToken: String
    }
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  },
  referralCode: {
    type: String,
    unique: true,
    required: false
  },
  referralUsed: {
    type: String,
    required: false,
    default: 'null'
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  TwoFactorAuth: {
    type: Boolean,
    default: false
  },
  // Server-side 2FA. A password login for a 2FA account gets a token marked
  // mfa:'pending' carrying this jti; the token only works once a correct code
  // moves the jti into mfaVerifiedJtis. Before this, 2FA existed only in the
  // app: /login returned a fully working token and the OTP screen was cosmetic.
  mfaPendingJti: { type: String, select: false },
  mfaVerifiedJtis: { type: [String], default: [], select: false },
  // Failed OTP guesses since the last code was issued; a new code resets it.
  otpFailedAttempts: { type: Number, default: 0, select: false },
  emailVerificationToken: String,
  emailVerificationExpire: Date,
  emailVerificationOTP: String,
  emailVerificationOTPExpire: Date,
  // Set when the emailed code is verified (verify-email-otp); only then may
  // PUT /resetpassword change the password, once, within the window.
  passwordResetAllowedUntil: { type: Date, select: false },
}, {
  timestamps: true
});

// Encrypt password using bcrypt and generate referral code
userSchema.pre('save', async function(next) {
  // Hash password if modified
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }

  // Generate unique referral code for new users
  if (this.isNew && !this.referralCode) {
    let isUnique = false;
    let referralCode;

    while (!isUnique) {
      referralCode = generateReferralCode();
      const existingUser = await mongoose.model('User').findOne({ referralCode });
      if (!existingUser) {
        isUnique = true;
      }
    }

    this.referralCode = referralCode;
  }

  next();
});

// Sign JWT and return
userSchema.methods.getSignedJwtToken = function(options = {}) {
  const payload = { id: this._id };
  const signOptions = { expiresIn: process.env.JWT_EXPIRE, algorithm: 'HS256' };
  if (options.mfaPending) {
    payload.mfa = 'pending';
    signOptions.jwtid = options.jti;
  }
  return jwt.sign(payload, process.env.JWT_SECRET, signOptions);
};

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate and hash password token
userSchema.methods.getResetPasswordToken = function() {
  // Generate token
  const resetToken = crypto.randomBytes(20).toString('hex');

  // Hash token and set to resetPasswordToken field
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // Set expire
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

  return resetToken;
};

// Generate and hash email verification token
userSchema.methods.getEmailVerificationToken = function() {
  // Generate token
  const verificationToken = crypto.randomBytes(20).toString('hex');

  // Hash token and set to emailVerificationToken field
  this.emailVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');

  // Set expire (24 hours)
  this.emailVerificationExpire = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  return verificationToken;
};

// Generate email verification OTP
userSchema.methods.generateEmailVerificationOTP = function() {
  // Generate 6-digit OTP. crypto.randomInt, not Math.random: these codes gate
  // email changes and 2FA, so they must not be predictable.
  const otp = crypto.randomInt(100000, 1000000).toString();
  this.otpFailedAttempts = 0;

  // Set OTP and expiry (10 minutes)
  this.emailVerificationOTP = otp;
  this.emailVerificationOTPExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

  return otp;
};

module.exports = mongoose.model('User', userSchema);
