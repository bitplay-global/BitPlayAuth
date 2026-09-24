const mongoose = require('mongoose');
const User = require('../models/User');

const REFERRAL_CODE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

const generateReferralCode = () => {
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += REFERRAL_CODE_CHARS.charAt(Math.floor(Math.random() * REFERRAL_CODE_CHARS.length));
  }
  return result;
};

/**
 * Assigns a referral code to a user that somehow has none (legacy accounts
 * created before the field existed -- the User pre-save hook covers every new
 * account).
 *
 * Retries until the generated code is actually unused. The previous version
 * generated a single unchecked code, so a collision hit the unique index.
 * Returns null if a code could not be assigned; the caller keeps going either
 * way, because failing to backfill a code must never fail a login.
 */
async function assignMissingReferralCode(userId) {
  if (!mongoose.Types.ObjectId.isValid(userId)) return null;

  for (let attempt = 0; attempt < 10; attempt++) {
    const candidate = generateReferralCode();
    if (await User.findOne({ referralCode: candidate }).select('_id').lean()) continue;
    try {
      const updated = await User.findByIdAndUpdate(
        userId,
        { referralCode: candidate },
        { new: true, runValidators: true }
      );
      if (updated) return updated.referralCode;
      return null; // user vanished mid-request
    } catch (err) {
      if (err && err.code === 11000) continue; // lost a race, try another code
      throw err;
    }
  }
  return null;
}

// Get token from model, create cookie and send response
const sendTokenResponse = async (user, statusCode, res, extra = {}, tokenOptions = {}) => {
  try {
    // Create token
    const token = user.getSignedJwtToken(tokenOptions);

    const options = {
      expires: new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
      ),
      httpOnly: true
    };

    if (process.env.NODE_ENV === 'production') {
      options.secure = true;
    }

    // A user's referral code is PERMANENT once assigned. It is only minted here
    // when genuinely absent.
    //
    // This used to regenerate a code on every login for any user whose
    // referralCode was falsy, and write it without awaiting or catching. Two
    // consequences: a legacy user got a different code on each login -- which
    // silently orphaned everyone they had already referred, since children
    // store the code STRING rather than the parent's id -- and a rejected write
    // surfaced as an unhandled rejection, which Node treats as fatal.
    let referralCode = user.referralCode;
    if (!referralCode) {
      referralCode = await assignMissingReferralCode(user._id);
    }

    res.status(statusCode)
      .cookie('token', token, options)
      .json({
        success: true,
        token,
        ...extra,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          isActive: user.isActive,
          referralCode: referralCode || null,
          emailVerified: user.emailVerified,
          createdAt: user.createdAt,
          twofactor: user.TwoFactorAuth
        }
      });
  } catch (err) {
    // Callers invoke this without awaiting, so anything thrown here would be an
    // unhandled rejection rather than a response.
    console.error('sendTokenResponse error:', err);
    if (!res.headersSent) {
      res.status(500).json({ success: false, message: 'Authentication failed' });
    }
  }
};

module.exports = sendTokenResponse;
