const express = require('express');
const {
  register,
  login,
  socialLogin,
  getMe,
  forgotPassword,
  resetPassword,
  logout,
  verifyEmail,
  verifyEmailOTP,
  resendEmailVerification,
  updateProfile,
  updateemailotp,
  updateemail,
  TwoFactorOTP,
  VerifyTwoFaOTP,
  claimReferral
} = require('../controllers/authController');

const auth = require('../middleware/auth');
const User = require('../models/User');

const router = express.Router();

/** Escapes regex metacharacters so user input inside a $regex is a literal. */
const escapeRegex = (value) => String(value ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

router.get("/referrals", async (req, res) => {
  try {
    const { code } = req.query;

    if (!code || typeof code !== "string") {
      return res.status(400).json({
        success: false,
        message: "Referral code is required",
      });
    }

    // Count only active users with this referral code (case-insensitive)
    const count = await User.countDocuments({
      referralUsed: { $regex: `^${escapeRegex(code)}$`, $options: "i" },
      isActive: true
    });

    res.json({
      success: true,
      referralCode: code,
      count,
    });
  } catch (error) {
    console.error("Fetching error:", error.message);
    res.status(500).json({
      success: false,
      message: "Failed to fetch user referrals",
    });
  }
});

// Public routes
router.post('/register', register);
router.post('/login', login);
router.post('/social-login', socialLogin);
router.post('/forgotpassword', forgotPassword);
router.put('/resetpassword/:resettoken', resetPassword);
router.put('/update-profile', auth, updateProfile);
router.get('/verify-email/:token', verifyEmail);
router.get('/verify-email-otp/:otp/:email', verifyEmailOTP);
router.post('/resend-verification', resendEmailVerification);
router.post('/update-email-otp', updateemailotp);
router.post('/update-email', updateemail);
router.post('/two-factor-otp', TwoFactorOTP);
router.post('/verify-twofactorotp', VerifyTwoFaOTP);

// Protected routes
router.get('/me', auth, getMe);
router.post('/referral/claim', auth, claimReferral);
router.get('/logout', auth, logout);

module.exports = router;
