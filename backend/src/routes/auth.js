const express = require('express');
const { 
    registerUser, 
    loginUser, 
    logoutUser, 
    refreshToken, 
    forgotPassword, 
    resetPassword, 
    changePassword, 
    verifyEmail, 
    confirmEmailChange, 
    getUserProfile, 
    updateUserProfile, 
    changeEmail, 
    updateUserSettings, 
    setupMFA, 
    verifyMFA, 
    getActiveSessions, 
    revokeSession, 
    deactivateAccount, 
    reactivateAccount 
} = require('../controllers/authController');
const router = express.Router();

// Authentication Routes

// Register a new user
router.post('/user/auth/register', registerUser);

// Login a user
router.post('/user/auth/login', loginUser);

// Logout a user
router.post('/user/auth/logout', logoutUser);

// Refresh authentication token
router.post('/user/auth/refresh-token', refreshToken);

// Forgot password and send reset link
router.post('/user/auth/forgot-password', forgotPassword);

// Reset password using a reset token
router.post('/user/auth/reset-password/:token', resetPassword);

// Change user password
router.post('/user/auth/change-password', changePassword);

// Verify email for new users
router.get('/user/auth/verify-email/:token', verifyEmail);

// Confirm email change
router.get('/user/auth/confirm-email-change/:token', confirmEmailChange);

// Get logged-in user's profile
router.get('/user/auth/me', getUserProfile);

// Update user's profile
router.put('/user/auth/me', updateUserProfile);

// Change email address
router.post('/user/auth/change-email', changeEmail);

// Update user settings
router.put('/user/auth/settings', updateUserSettings);

// Set up multi-factor authentication (MFA)
router.post('/user/auth/setup-mfa', setupMFA);

// Verify MFA code
router.post('/user/auth/verify-mfa', verifyMFA);

// Get active sessions for the user
router.get('/user/auth/sessions', getActiveSessions);

// Revoke a session
router.post('/user/auth/revoke-session', revokeSession);

// Deactivate user account
router.post('/user/auth/deactivate-account', deactivateAccount);

// Reactivate deactivated user account
router.post('/user/auth/reactivate-account', reactivateAccount);

module.exports = router;
