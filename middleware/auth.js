const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided, authorization denied'
      });
    }

    // Algorithm pinned so a token cannot pick its own verification scheme.
    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    const user = await User.findById(decoded.id).select('-password +mfaVerifiedJtis');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Token is not valid'
      });
    }

    // A 2FA login token is unusable until its code has been entered.
    if (decoded.mfa === 'pending' && !(user.mfaVerifiedJtis || []).includes(decoded.jti)) {
      return res.status(401).json({
        success: false,
        message: 'Two-factor verification required',
        code: 'MFA_REQUIRED'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(401).json({
      success: false,
      message: 'Token is not valid'
    });
  }
};

module.exports = auth;
