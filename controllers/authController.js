const crypto = require('crypto');

// A 6-digit code allows 1,000,000 guesses; stop after a handful.
const MAX_OTP_ATTEMPTS = 5;
// How many 2FA-verified login sessions an account keeps at once.
const MAX_VERIFIED_SESSIONS = 10;
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');
const sendTokenResponse = require('../utils/sendTokenResponse');
const { isDisposableEmail } = require('../utils/disposableEmail');
const { verifySocialIdentity } = require('../utils/verifySocialToken');

/** Escapes regex metacharacters so user input inside a $regex is a literal. */
const escapeRegex = (value) => String(value ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res, next) => {
  try {
    const { name, email, password, referral_code } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide name, email and password'
      });
    }

    // Throwaway addresses are refused at sign-up only. Existing accounts are
    // never re-checked -- whatever anyone already registered with keeps working.
    if (isDisposableEmail(email)) {
      console.log(`[Register] Refused disposable address: ${String(email).split('@')[1]}`);
      return res.status(400).json({
        success: false,
        message: 'Please sign up with a permanent email address. Temporary and disposable email providers are not accepted.',
        code: 'DISPOSABLE_EMAIL'
      });
    }

    var used_referral = 'null';

    // Validate referral code if provided
    if (referral_code && referral_code.trim() !== '') {
      const trimmedCode = referral_code.trim();
      // Escaped: unescaped, a submitted code of `.*` matched an arbitrary user,
      // passed validation, and attached the new account to whoever matched first.
      const referringUser = await User.findOne({
        referralCode: { $regex: `^${escapeRegex(trimmedCode)}$`, $options: 'i' }
      });

      if (!referringUser) {
        return res.status(400).json({
          success: false,
          message: 'Invalid referral code. Please check the code and try again.'
        });
      }

      used_referral = trimmedCode;
      console.log(`Valid referral code ${used_referral} used`);
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    // The referral code is deliberately NOT generated here. The User model's
    // pre-save hook generates one and retries until it is unique; passing a
    // pre-generated code skipped that loop entirely, so a collision hit the
    // schema's unique index and surfaced to the user as an unexplained 500.
    const user = await User.create({
      name,
      email,
      password,
      emailVerified: false,
      referralUsed: used_referral
    });

    // Generate email verification OTP
    const verificationOTP = user.generateEmailVerificationOTP();
    await user.save({ validateBeforeSave: false });

    const message = `Your email verification OTP is: ${verificationOTP}\n\nThis OTP will expire in 10 minutes.`;
    const htmlMessage = `
      <h2>Email Verification</h2>
      <p>Your email verification OTP is:</p>
      <h1 style="color: #4CAF50; font-size: 32px; letter-spacing: 5px;">${verificationOTP}</h1>
      <p>Please enter this OTP in the app to verify your email.</p>
      <p>This OTP will expire in 10 minutes.</p>
    `;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Email Verification',
        message,
        html: htmlMessage
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully. Please check your email to verify your account.',
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          emailVerified: user.emailVerified,
          referralCode: user.referralCode
        }
      });
    } catch (err) {
      console.error('Email send error:', err);
      user.emailVerificationToken = undefined;
      user.emailVerificationExpire = undefined;
      await user.save({ validateBeforeSave: false });

      res.status(201).json({
        success: true,
        message: 'User registered successfully, but email verification could not be sent. Please contact support.',
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          emailVerified: user.emailVerified,
          referralCode: user.referralCode
        }
      });
    }
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Validate email & password
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email and password'
      });
    }

    // Check for user
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if password matches
    const isMatch = await user.matchPassword(password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if email is verified
    if (!user.emailVerified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email before logging in',
        emailVerified: false,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          referral: user.referralCode,
          twofactor: user.TwoFactorAuth
        }
      });
    }

    // 2FA accounts get a token that stays unusable until the code is entered.
    // The response shape is unchanged, so app builds already in use -- which
    // carry this token to the OTP screen and log in with it afterwards -- keep
    // working, but the token alone no longer grants access.
    let tokenOptions = {};
    if (user.TwoFactorAuth === true) {
      const jti = crypto.randomBytes(16).toString('hex');
      user.mfaPendingJti = jti;
      tokenOptions = { mfaPending: true, jti };
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    sendTokenResponse(user, 200, res, {}, tokenOptions);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
};

// @desc    Get current logged in user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        gender: user.gender,
        phoneNumber: user.phoneNumber,
        country: user.country,
        city: user.city,
        photo: user.photo,
        isActive: user.isActive,
        referralCode: user.referralCode,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get me error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Update user profile
// @route   PUT /api/auth/update-profile
// @access  Private
exports.updateProfile = async (req, res, next) => {
  try {
    const { name, gender, phoneNumber, country, city } = req.body;

    // Find user by ID from auth middleware
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Update only the fields that are provided
    if (name !== undefined) user.name = name;
    if (gender !== undefined) user.gender = gender;
    if (phoneNumber !== undefined) user.phoneNumber = phoneNumber;
    if (country !== undefined) user.country = country;
    if (city !== undefined) user.city = city;

    // Save the updated user
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        gender: user.gender,
        phoneNumber: user.phoneNumber,
        country: user.country,
        city: user.city,
        photo: user.photo,
        isActive: user.isActive,
        referralCode: user.referralCode,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);

    // Handle validation errors
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: messages.join(', ')
      });
    }

    res.status(500).json({
      success: false,
      message: 'Server error while updating profile'
    });
  }
};

// @desc    Forgot password
// @route   POST /api/auth/forgotpassword
// @access  Public
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email address'
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'There is no user with that email'
      });
    }

    // Get reset token
    const resetToken = user.generateEmailVerificationOTP();

    await user.save({ validateBeforeSave: false });

    const message = `You are receiving this email because you have requested to reset password`;

    const htmlMessage = `
      <h1>Password Reset Request</h1>
      <p>You are receiving this email because you (or someone else) has requested the reset of a password.</p>
      <p>Please use the code below to reset your password:</p>
      <p>${resetToken}</p>
      <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
      <p>This code will expire in 10 minutes.</p>
    `;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Password Reset Token',
        message,
        html: htmlMessage
      });

      res.status(200).json({
        success: true,
        message: 'Email sent successfully'
      });
    } catch (err) {
      console.error('Email send error:', err);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;

      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        success: false,
        message: 'Email could not be sent'
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Reset password
// @route   PUT /api/auth/resetpassword/:resettoken
// @access  Public
exports.resetPassword = async (req, res, next) => {
  try {
    // Get hashed token
    const user = await User.findOne({
      email: req.params.resettoken
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP'
      });
    }

    // Set new password
    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    sendTokenResponse(user, 200, res);
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};


// @desc    Logout user / clear cookie
// @route   GET /api/auth/logout
// @access  Private
exports.logout = async (req, res, next) => {
  res.cookie('token', 'none', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });

  res.status(200).json({
    success: true,
    message: 'User logged out successfully'
  });
};

// @desc    Social login (Google, Facebook, LinkedIn)
// @route   POST /api/auth/social-login
// @access  Public
exports.socialLogin = async (req, res, next) => {
  try {
    const { provider, providerId, name, photo, accessToken, idToken, firebaseIdToken, referral_code } = req.body;

    // Validation
    if (!provider || !providerId || !req.body.email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide provider, providerId, and email'
      });
    }

    // Prove the sign-in with the provider before touching any account. This
    // endpoint used to trust `email` from the body, so anyone could log in as
    // anyone. The email used from here on is the one Google/Apple/Firebase
    // vouches for; the body's is ignored.
    let verified;
    try {
      verified = await verifySocialIdentity({ provider, accessToken, idToken, firebaseIdToken });
    } catch (verifyErr) {
      console.warn(`[SocialLogin] Rejected unverified sign-in (${provider}): ${verifyErr.code || verifyErr.message}`);
      return res.status(401).json({
        success: false,
        message: 'We could not verify this sign-in. Please try again.',
        code: 'SOCIAL_VERIFICATION_FAILED'
      });
    }
    const email = verified.email;
    if (String(req.body.email).trim().toLowerCase() !== email) {
      console.warn(`[SocialLogin] Body email differed from the verified one; using the verified address (${verified.method})`);
    }

    // Check if user already exists with this email
    let user = await User.findOne({ email });
    const isNewUser = !user;

    // Same rule for social sign-ups, but only when the account is being created.
    // An existing user signing in again is never re-checked, whatever address
    // they already have. Apple's private relay is not on the list, so Sign in
    // with Apple keeps working.
    if (isNewUser && isDisposableEmail(email)) {
      console.log(`[SocialLogin] Refused disposable address: ${String(email).split('@')[1]}`);
      return res.status(400).json({
        success: false,
        message: 'Please sign up with a permanent email address. Temporary and disposable email providers are not accepted.',
        code: 'DISPOSABLE_EMAIL'
      });
    }

    if (user) {
      // User exists, update social provider info if not already set
      if (!user.socialProviders) {
        user.socialProviders = {};
      }

      if (!user.socialProviders[provider]) {
        user.socialProviders[provider] = {
          id: providerId,
          accessToken: accessToken
        };
        await user.save();
      }
    } else {
      // Attribute the referral, exactly as /register does. Without this, every
      // Google/Apple/Facebook signup was created with referralUsed 'null' and
      // could never be credited to the person who invited them.
      // Unlike /register this does NOT reject an unknown code: the user is
      // already authenticated with the provider at this point, and failing the
      // signup over a bad referral would strand them with no way to retry.
      let used_referral = 'null';
      if (referral_code && String(referral_code).trim() !== '') {
        const trimmedCode = String(referral_code).trim();
        const referringUser = await User.findOne({
          referralCode: { $regex: `^${escapeRegex(trimmedCode)}$`, $options: 'i' }
        });
        if (referringUser) {
          used_referral = trimmedCode;
          console.log(`Valid referral code ${used_referral} used (social signup)`);
        } else {
          console.log(`Ignoring unknown referral code on social signup: ${trimmedCode}`);
        }
      }

      // Create new user with social provider info
      user = await User.create({
        name: name || 'Social User',
        email,
        password: crypto.randomBytes(32).toString('hex'), // Random password for social users
        photo,
        socialProviders: {
          [provider]: {
            id: providerId,
            accessToken: accessToken
          }
        },
        referralUsed: used_referral,
        isActive: true,
        emailVerified: true // Social logins are pre-verified
      });
    }

    // isNewUser lets the app offer a referral code to someone who signed up
    // through the Login screen, which has no referral field of its own.
    sendTokenResponse(user, 200, res, { isNewUser });
  } catch (error) {
    console.error('Social login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during social login'
    });
  }
};

// @desc    Verify email
// @route   GET /api/auth/verify-email/:token
// @access  Public
exports.verifyEmail = async (req, res, next) => {
  try {
    // Get hashed token
    const emailVerificationToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      emailVerificationToken,
      emailVerificationExpire: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token'
      });
    }

    // Set email as verified
    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpire = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during email verification'
    });
  }
};

// @desc    Verify email with OTP
// @route   GET /api/auth/verify-email-otp/:otp/:email
// @access  Public
exports.verifyEmailOTP = async (req, res, next) => {
  try {
    const { otp, email } = req.params;

    // TEMPORARY: Accept any 4-digit OTP for development
    // if (otp && otp.length === 4 && /^\d{4}$/.test(otp)) {
    //   console.log(`Development mode: Accepting any 4-digit OTP: ${otp} for email: ${email}`);

    //   // Find specific user by email with unverified status
    //   const user = await User.findOne({
    //     email: email.toLowerCase()
    //   });

    //   if (!user) {
    //     return res.status(400).json({
    //       success: false,
    //       message: `No unverified user found with email: ${email}`
    //     });
    //   }

    //   // Set email as verified
    //   user.emailVerified = true;
    //   user.emailVerificationOTP = undefined;
    //   user.emailVerificationOTPExpire = undefined;
    //   await user.save();

    //   console.log(`Email verified successfully for user: ${user.email}`);

    //   return res.status(200).json({
    //     success: true,
    //     message: 'Email verified successfully with OTP (Development Mode)',
    //     user: {
    //       id: user._id,
    //       name: user.name,
    //       email: user.email,
    //       emailVerified: true
    //     }
    //   });
    // }

    // Original OTP validation (for production)
    const user = await User.findOne({
      emailVerificationOTP: otp,
      emailVerificationOTPExpire: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP'
      });
    }

    // Set email as verified
    user.emailVerified = true;
    user.emailVerificationOTP = undefined;
    user.emailVerificationOTPExpire = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Email verified successfully with OTP'
    });
  } catch (error) {
    console.error('Email OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during OTP verification'
    });
  }
};

// @desc    Resend email verification
// @route   POST /api/auth/resend-verification
// @access  Public
exports.resendEmailVerification = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email address'
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.emailVerified) {
      return res.status(400).json({
        success: false,
        message: 'Email is already verified'
      });
    }

    // Generate new verification token
    const verificationToken = user.getEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    // Create verification URL
    const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${verificationToken}`;

    const message = `Please verify your email by clicking on this link: \n\n ${verificationUrl}`;
    const htmlMessage = `
      <h2>Email Verification</h2>
      <p>Please verify your email by clicking the link below:</p>
      <a href="${verificationUrl}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a>
      <p>If the button doesn't work, copy and paste this link in your browser:</p>
      <p>${verificationUrl}</p>
      <p>This link will expire in 24 hours.</p>
    `;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Email Verification',
        message,
        html: htmlMessage
      });

      res.status(200).json({
        success: true,
        message: 'Verification email sent successfully'
      });
    } catch (err) {
      console.error('Email send error:', err);
      user.emailVerificationToken = undefined;
      user.emailVerificationExpire = undefined;
      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        success: false,
        message: 'Email could not be sent'
      });
    }
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Update Email OTP
// @route   POST /api/auth/update-email-otp
// @access  Public
exports.updateemailotp = async (req, res, next) => {
  try {
    const { email, new_email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email address'
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'There is no user with that email'
      });
    }

    // Get reset token
    const UpdateOTP = user.generateEmailVerificationOTP();

    await user.save({ validateBeforeSave: false });

    const message = `You are receiving this email because you have requested to change email`;

    const htmlMessage = `
      <h1>Email Change Request</h1>
      <p>You are receiving this email because you have requested to update email.</p>
      
      <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
      <p>This code will expire in 10 minutes.</p>
    `;

    const NewMessage = `You are receiving this email because you have requested to change email`;

    const NewHtmlMessage = `
      <h1>Email Change Request</h1>
      <p>You are receiving this email because you have requested to update email.</p>

      <p>Please use the code below to update your email:</p>
      <p>${UpdateOTP}</p>
      
      <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
      <p>This code will expire in 10 minutes.</p>
    `;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Updating Email',
        message,
        html: htmlMessage
      });

      await sendEmail({
        email: new_email,
        subject: 'Update User Email',
        NewMessage,
        html: NewHtmlMessage
      });

      res.status(200).json({
        success: true,
        message: 'Email sent successfully'
      });
    } catch (err) {
      console.error('Email send error:', err);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;

      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        success: false,
        message: 'Email could not be sent'
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    UpadteEmail
// @route   POST /api/auth/updateemail
// @access  Public
exports.updateemail = async (req, res, next) => {
  try {
    const { email, new_email, otp } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email address'
      });
    }

    if (!new_email) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an email address that needs to be updated'
      });
    }

    const accountEmail = String(email).trim().toLowerCase();
    const user = await User.findOne({
      emailVerificationOTP: String(otp),
      emailVerificationOTPExpire: { $gt: Date.now() },
      email: accountEmail
    }).select('+otpFailedAttempts');

    if (!user) {
      await User.updateOne({ email: accountEmail }, { $inc: { otpFailedAttempts: 1 } });
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP'
      });
    }

    if ((user.otpFailedAttempts || 0) >= MAX_OTP_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        message: 'Too many incorrect attempts. Please request a new code.'
      });
    }

    try {
      // Single use: the code must not work a second time.
      user.emailVerificationOTP = undefined;
      user.emailVerificationOTPExpire = undefined;
      user.otpFailedAttempts = 0;
      user.email = new_email;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;

      await user.save();

      res.status(200).json({
        success: true,
        message: 'Email updated successfully'
      });

    } catch (err) {
      console.error('Email send error:', err);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;

      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        success: false,
        message: 'Email could not be sent'
      });
    }
  } catch (error) {
    console.error('Update Email error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Send Two Factor OTP
// @route   POST /api/auth/two-factor-otp
// @access  Public
exports.TwoFactorOTP = async (req, res, next) => {
  try {
    const { user_id } = req.body;

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: 'Please provide an user id'
      });
    }

    const user = await User.findById(user_id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'There is no user with that user id'
      });
    }

    // Get reset token
    const UpdateOTP = user.generateEmailVerificationOTP();

    await user.save({ validateBeforeSave: false });

    const NewMessage = `You are receiving this email because Two Factor Authentication is Enabled`;

    const NewHtmlMessage = `
      <h1>Two Factor OTP</h1>

      <p>Please use the code below to login:</p>
      <p>${UpdateOTP}</p>
      
      <p>If you did not request this, please ignore this email.</p>
      <p>This code will expire in 10 minutes.</p>
    `;

    try {

      await sendEmail({
        email: user.email,
        subject: 'Two Factor Authentication',
        NewMessage,
        html: NewHtmlMessage
      });

      res.status(200).json({
        success: true,
        message: 'Email sent successfully',
        email: user.email
      });
    } catch (err) {
      console.error('Email send error:', err);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;

      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        success: false,
        message: 'Email could not be sent'
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Verify Two Factor OTP
// @route   POST /api/auth/verify-twofactorotp
// @access  Public
exports.VerifyTwoFaOTP = async (req, res, next) => {
  try {
    const { otp, email } = req.body;
    // The code is no longer logged: it used to be written to the server log in clear.

    if (!otp) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid OTP'
      });
    }

    // Builds that send the email get the lookup scoped to that account. Older
    // builds send only the code, so it still works without one, but then a
    // failed guess cannot be counted against a particular account.
    const query = {
      emailVerificationOTP: String(otp),
      emailVerificationOTPExpire: { $gt: Date.now() },
    };
    const scopedEmail = email ? String(email).trim().toLowerCase() : null;
    if (scopedEmail) query.email = scopedEmail;

    const user = await User.findOne(query).select('+mfaPendingJti +mfaVerifiedJtis +otpFailedAttempts');

    if (!user) {
      if (scopedEmail) {
        await User.updateOne({ email: scopedEmail }, { $inc: { otpFailedAttempts: 1 } });
      }
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired OTP'
      });
    }

    if ((user.otpFailedAttempts || 0) >= MAX_OTP_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        message: 'Too many incorrect attempts. Please request a new code.'
      });
    }

    // Single use: a code that has worked once must not work again.
    user.emailVerificationOTP = undefined;
    user.emailVerificationOTPExpire = undefined;
    user.otpFailedAttempts = 0;

    // Unlock the login token this code was issued for.
    if (user.mfaPendingJti) {
      user.mfaVerifiedJtis = [...(user.mfaVerifiedJtis || []), user.mfaPendingJti].slice(-MAX_VERIFIED_SESSIONS);
      user.mfaPendingJti = undefined;
    }

    await user.save({ validateBeforeSave: false });
    return res.status(200).json({
      success: true,
      message: 'OTP verified successfully'
    });
  } catch (error) {
    console.error('Verifying OTP error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
};

// @desc    Attach a referrer to an account that does not have one yet
// @route   POST /api/auth/referral/claim
// @access  Private
exports.claimReferral = async (req, res) => {
  try {
    const { referral_code } = req.body;
    const code = String(referral_code ?? '').trim();

    if (!code) {
      return res.status(400).json({ success: false, message: 'Referral code is required' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Write-once. Without this, a user could re-point their referrer at will
    // and move a recurring 5%/day payout between accounts.
    const alreadySet = user.referralUsed && String(user.referralUsed).trim().toLowerCase() !== 'null';
    if (alreadySet) {
      return res.status(409).json({ success: false, message: 'A referral code has already been applied to this account.' });
    }

    const referringUser = await User.findOne({
      referralCode: { $regex: `^${escapeRegex(code)}$`, $options: 'i' }
    });
    if (!referringUser) {
      return res.status(400).json({ success: false, message: 'Invalid referral code. Please check the code and try again.' });
    }

    if (String(referringUser._id) === String(user._id)) {
      return res.status(400).json({ success: false, message: 'You cannot use your own referral code.' });
    }

    user.referralUsed = code;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json({ success: true, message: 'Referral code applied.', referralUsed: code });
  } catch (error) {
    console.error('Claim referral error:', error);
    return res.status(500).json({ success: false, message: 'Server error while applying referral code' });
  }
};
