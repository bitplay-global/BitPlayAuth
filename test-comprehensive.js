const axios = require('axios');

const BASE_URL = 'http://localhost:5000/api';

// Test data with unique email each time
const testUser = {
  name: 'Test User',
  email: `test${Date.now()}@example.com`,
  password: 'password123'
};

let authToken = '';

// Helper function to make requests
const makeRequest = async (method, url, data = null, headers = {}) => {
  try {
    const config = {
      method,
      url: `${BASE_URL}${url}`,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };

    if (data) {
      config.data = data;
    }

    const response = await axios(config);
    return { success: true, data: response.data, status: response.status };
  } catch (error) {
    return {
      success: false,
      error: error.response?.data || error.message,
      status: error.response?.status
    };
  }
};

// Test functions
const testHealthCheck = async () => {
  console.log('\n🔍 Testing Health Check...');
  const result = await makeRequest('GET', '/health');
  
  if (result.success) {
    console.log('✅ Health check passed');
    console.log('📊 Server Status:', result.data.message);
    console.log('🕐 Timestamp:', result.data.timestamp);
    console.log('🌍 Environment:', result.data.environment);
  } else {
    console.log('❌ Health check failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

const testRegister = async () => {
  console.log('\n📝 Testing User Registration...');
  console.log('📧 Test Email:', testUser.email);
  
  const result = await makeRequest('POST', '/auth/register', testUser);
  
  if (result.success) {
    console.log('✅ Registration successful');
    console.log('👤 User ID:', result.data.user.id);
    console.log('📧 Email:', result.data.user.email);
    console.log('👤 Name:', result.data.user.name);
    console.log('🔑 Token received:', result.data.token ? 'Yes' : 'No');
    authToken = result.data.token;
  } else {
    console.log('❌ Registration failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

const testLogin = async () => {
  console.log('\n🔐 Testing User Login...');
  const loginData = {
    email: testUser.email,
    password: testUser.password
  };
  
  const result = await makeRequest('POST', '/auth/login', loginData);
  
  if (result.success) {
    console.log('✅ Login successful');
    console.log('👤 User ID:', result.data.user.id);
    console.log('📧 Email:', result.data.user.email);
    console.log('🕐 Last Login:', result.data.user.lastLogin || 'First login');
    authToken = result.data.token;
  } else {
    console.log('❌ Login failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

const testGetMe = async () => {
  console.log('\n👤 Testing Get Current User...');
  
  if (!authToken) {
    console.log('❌ No auth token available');
    return false;
  }
  
  const result = await makeRequest('GET', '/auth/me', null, {
    'Authorization': `Bearer ${authToken}`
  });
  
  if (result.success) {
    console.log('✅ Get current user successful');
    console.log('👤 User ID:', result.data.user.id);
    console.log('📧 Email:', result.data.user.email);
    console.log('🕐 Last Login:', result.data.user.lastLogin);
    console.log('📅 Created:', result.data.user.createdAt);
  } else {
    console.log('❌ Get current user failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

const testInvalidLogin = async () => {
  console.log('\n🚫 Testing Invalid Login...');
  const invalidData = {
    email: testUser.email,
    password: 'wrongpassword'
  };
  
  const result = await makeRequest('POST', '/auth/login', invalidData);
  
  if (!result.success && result.status === 401) {
    console.log('✅ Invalid login correctly rejected');
    console.log('📝 Error message:', result.error.message);
  } else {
    console.log('❌ Invalid login test failed - should have been rejected');
    console.log('Result:', result);
  }
  
  return !result.success && result.status === 401;
};

const testUnauthorizedAccess = async () => {
  console.log('\n🔒 Testing Unauthorized Access...');
  
  const result = await makeRequest('GET', '/auth/me', null, {
    'Authorization': 'Bearer invalid_token'
  });
  
  if (!result.success && result.status === 401) {
    console.log('✅ Unauthorized access correctly blocked');
    console.log('📝 Error message:', result.error.message);
  } else {
    console.log('❌ Unauthorized access test failed - should have been blocked');
    console.log('Result:', result);
  }
  
  return !result.success && result.status === 401;
};

const testForgotPassword = async () => {
  console.log('\n🔄 Testing Forgot Password...');
  const forgotData = {
    email: testUser.email
  };
  
  const result = await makeRequest('POST', '/auth/forgotpassword', forgotData);
  
  if (result.success) {
    console.log('✅ Forgot password request successful');
    console.log('📧 Message:', result.data.message);
    console.log('⚠️  Note: Email sending may fail if SMTP is not configured');
  } else {
    console.log('❌ Forgot password request failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

const testLogout = async () => {
  console.log('\n🚪 Testing Logout...');
  
  if (!authToken) {
    console.log('❌ No auth token available');
    return false;
  }
  
  const result = await makeRequest('GET', '/auth/logout', null, {
    'Authorization': `Bearer ${authToken}`
  });
  
  if (result.success) {
    console.log('✅ Logout successful');
    console.log('📝 Message:', result.data.message);
  } else {
    console.log('❌ Logout failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

// Main test runner
const runComprehensiveTests = async () => {
  console.log('🚀 Starting Comprehensive API Tests...');
  console.log('🌐 Server URL: http://localhost:5000');
  console.log('📧 Test Email:', testUser.email);
  console.log('=' .repeat(60));
  
  const tests = [
    { name: 'Health Check', fn: testHealthCheck },
    { name: 'User Registration', fn: testRegister },
    { name: 'User Login', fn: testLogin },
    { name: 'Get Current User', fn: testGetMe },
    { name: 'Invalid Login', fn: testInvalidLogin },
    { name: 'Unauthorized Access', fn: testUnauthorizedAccess },
    { name: 'Forgot Password', fn: testForgotPassword },
    { name: 'User Logout', fn: testLogout }
  ];
  
  let passed = 0;
  let failed = 0;
  const results = [];
  
  for (const test of tests) {
    const result = await test.fn();
    results.push({ name: test.name, passed: result });
    if (result) {
      passed++;
    } else {
      failed++;
    }
  }
  
  console.log('\n' + '=' .repeat(60));
  console.log('📊 COMPREHENSIVE TEST RESULTS');
  console.log('=' .repeat(60));
  
  results.forEach(result => {
    const icon = result.passed ? '✅' : '❌';
    console.log(`${icon} ${result.name}`);
  });
  
  console.log('\n📈 Summary:');
  console.log(`✅ Passed: ${passed}/${tests.length}`);
  console.log(`❌ Failed: ${failed}/${tests.length}`);
  console.log(`📊 Success Rate: ${((passed / tests.length) * 100).toFixed(1)}%`);
  
  if (failed === 0) {
    console.log('\n🎉 ALL TESTS PASSED! Your authentication API is working perfectly!');
    console.log('🚀 Ready for production use!');
  } else if (passed >= 6) {
    console.log('\n✨ Most tests passed! Your API is working well.');
    console.log('🔧 Check the failed tests for minor issues.');
  } else {
    console.log('\n⚠️  Several tests failed. Check server configuration and logs.');
  }
  
  console.log('\n🔗 API Endpoints Summary:');
  console.log('• POST /api/auth/register - User registration');
  console.log('• POST /api/auth/login - User login');
  console.log('• GET /api/auth/me - Get current user (protected)');
  console.log('• POST /api/auth/forgotpassword - Request password reset');
  console.log('• GET /api/auth/logout - Logout user (protected)');
  console.log('• GET /api/health - Health check');
};

// Run tests if this file is executed directly
if (require.main === module) {
  runComprehensiveTests().catch(console.error);
}

module.exports = { runComprehensiveTests };
