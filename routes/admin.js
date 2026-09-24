const express = require('express');
const User = require('../models/User');
const auth = require('../middleware/auth');

const router = express.Router();

// Admin middleware - simple check for now
const adminAuth = (req, res, next) => {
  // For now, just check if user is authenticated
  // In production, you'd check for admin role
  if (req.user) {
    next();
  } else {
    res.status(401).json({
      success: false,
      message: 'Admin access required'
    });
  }
};

// Get dashboard statistics
router.get('/dashboard', async (req, res) => {
  try {
    // Get total users
    const totalUsers = await User.countDocuments();
    
    // Get new users this month
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);
    
    const newUsersThisMonth = await User.countDocuments({
      createdAt: { $gte: startOfMonth }
    });
    
    // Get active users
    const activeUsers = await User.countDocuments({ isActive: true });
    
    // Get verified users
    const verifiedUsers = await User.countDocuments({ emailVerified: true });
    
    // Mock data for other stats (you can implement these based on your needs)
    const dashboardData = {
      totalRevenue: 12345.67,
      newUsers: newUsersThisMonth,
      transactions: 12, // Mock data
      supportTickets: 3, // Mock data
      totalUsers: totalUsers,
      activeUsers: activeUsers,
      verifiedUsers: verifiedUsers,
      recentTransactions: [
        {
          id: 'TXN001',
          user: 'John Doe',
          type: 'deposit',
          amount: 500.00,
          status: 'completed',
          date: new Date()
        },
        {
          id: 'TXN002',
          user: 'Jane Smith',
          type: 'withdrawal',
          amount: -200.00,
          status: 'pending',
          date: new Date()
        }
      ]
    };
    
    res.status(200).json({
      success: true,
      data: dashboardData
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard data'
    });
  }
});

// Get all users
router.get('/users', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const users = await User.find()
      .select('-password -resetPasswordToken -emailVerificationToken -emailVerificationOTP')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    const totalUsers = await User.countDocuments();
    
    res.status(200).json({
      success: true,
      data: users,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(totalUsers / limit),
        totalUsers: totalUsers,
        hasNext: page < Math.ceil(totalUsers / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching users'
    });
  }
});

// Get user by ID
router.get('/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -resetPasswordToken -emailVerificationToken -emailVerificationOTP');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    console.error('User fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user'
    });
  }
});

// Update user status
router.put('/users/:id/status', async (req, res) => {
  try {
    const { isActive } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { isActive },
      { new: true, runValidators: true }
    ).select('-password -resetPasswordToken -emailVerificationToken -emailVerificationOTP');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      success: true,
      data: user,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`
    });
  } catch (error) {
    console.error('User status update error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating user status'
    });
  }
});

// Delete user
router.delete('/users/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('User delete error:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting user'
    });
  }
});

// Get transactions (mock data for now)
router.get('/transactions', async (req, res) => {
  try {
    // Mock transaction data
    const transactions = [
      {
        id: 'TXN001',
        user: 'John Doe',
        type: 'deposit',
        amount: 500.00,
        status: 'completed',
        date: new Date()
      },
      {
        id: 'TXN002',
        user: 'Jane Smith',
        type: 'withdrawal',
        amount: 200.00,
        status: 'pending',
        date: new Date()
      },
      {
        id: 'TXN003',
        user: 'Mike Johnson',
        type: 'payment',
        amount: 150.00,
        status: 'completed',
        date: new Date()
      }
    ];
    
    res.status(200).json({
      success: true,
      data: transactions
    });
  } catch (error) {
    console.error('Transactions fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching transactions'
    });
  }
});

// Get support tickets (mock data for now)
router.get('/support', async (req, res) => {
  try {
    // Mock support ticket data
    const tickets = [
      {
        id: '001',
        subject: 'Login Issues',
        user: 'John Doe',
        priority: 'high',
        status: 'open',
        createdAt: new Date()
      },
      {
        id: '002',
        subject: 'Payment Failed',
        user: 'Jane Smith',
        priority: 'medium',
        status: 'in-progress',
        createdAt: new Date()
      },
      {
        id: '003',
        subject: 'Feature Request',
        user: 'Mike Johnson',
        priority: 'low',
        status: 'resolved',
        createdAt: new Date()
      }
    ];
    
    res.status(200).json({
      success: true,
      data: tickets
    });
  } catch (error) {
    console.error('Support tickets fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching support tickets'
    });
  }
});

// Update support ticket status
router.put('/support/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    
    // Mock response for now
    res.status(200).json({
      success: true,
      message: 'Support ticket status updated successfully'
    });
  } catch (error) {
    console.error('Support ticket update error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating support ticket status'
    });
  }
});

module.exports = router;
