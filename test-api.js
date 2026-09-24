const axios = require('axios');

const BASE_URL = 'http://localhost:5000/api';

// Test data
const testUser = {
  name: 'Test User',
  email: 'test@example.com',
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
    console.log('Response:', result.data);
  } else {
    console.log('❌ Health check failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

const testRegister = async () => {
  console.log('\n📝 Testing User Registration...');
  const result = await makeRequest('POST', '/auth/register', testUser);
  
  if (result.success) {
    console.log('✅ Registration successful');
    console.log('User:', result.data.user);
    authToken = result.data.token;
    console.log('Token received:', authToken ? 'Yes' : 'No');
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
    console.log('User:', result.data.user);
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
    console.log('User:', result.data.user);
  } else {
    console.log('❌ Get current user failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

const testForgotPassword = async () => {
  console.log('\n🔄 Testing Forgot Password...');
  const forgotData = {
    email: testUser.email
  };
  
  const result = await makeRequest('POST', '/auth/forgotpassword', forgotData);
  
  if (result.success) {
    console.log('✅ Forgot password request successful');
    console.log('Message:', result.data.message);
  } else {
    console.log('❌ Forgot password request failed');
    console.log('Error:', result.error);
  }
  
  return result.success;
};

// Main test runner
const runTests = async () => {
  console.log('🚀 Starting API Tests...');
  console.log('Make sure the server is running on http://localhost:5000');
  
  const tests = [
    { name: 'Health Check', fn: testHealthCheck },
    { name: 'User Registration', fn: testRegister },
    { name: 'User Login', fn: testLogin },
    { name: 'Get Current User', fn: testGetMe },
    { name: 'Forgot Password', fn: testForgotPassword }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const test of tests) {
    const result = await test.fn();
    if (result) {
      passed++;
    } else {
      failed++;
    }
  }
  
  console.log('\n📊 Test Results:');
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📈 Success Rate: ${((passed / tests.length) * 100).toFixed(1)}%`);
  
  if (failed === 0) {
    console.log('\n🎉 All tests passed! Your API is working correctly.');
  } else {
    console.log('\n⚠️  Some tests failed. Check the server logs and configuration.');
  }
};

// Run tests if this file is executed directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests };
