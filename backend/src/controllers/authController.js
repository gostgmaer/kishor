const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/userModel');

// REGISTER: Create a new user
exports.registerUser = async (req, res) => {
  const { firstName, lastName, email, password, role, status } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const newUser = new User({ firstName, lastName, email, password, role, status });
    await newUser.save();
    res.status(201).json({ message: 'User created successfully', user: newUser });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// LOGIN: Authenticate user and return JWT token
exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordValid = await user.matchPassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    const refreshToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '7d', // Refresh token lasts for 7 days
    });

    res.status(200).json({ message: 'Login successful', token, refreshToken });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// LOGOUT: User logout
exports.logoutUser = (req, res) => {
  res.status(200).json({ message: 'Logged out successfully' });
};

// PASSWORD RESET: Request password reset link
exports.resetPasswordRequest = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // In a real-world app, you'd send a reset email with a token here
    res.status(200).json({ message: 'Password reset link sent (not implemented)' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// PASSWORD UPDATE: Update the password after reset
exports.updatePassword = async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.password = newPassword;
    await user.save();
    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// VERIFY TOKEN: Middleware to verify if the token is valid
exports.verifyToken = (req, res) => {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = decoded;
    res.status(200).json({ message: 'Token is valid', user: req.user });
  });
};

// GET USER PROFILE: Get authenticated user's profile
exports.getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// UPDATE USER PROFILE: Update authenticated user's profile
exports.updateUserProfile = async (req, res) => {
  const { firstName, lastName, email, role, status } = req.body;

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.firstName = firstName || user.firstName;
    user.lastName = lastName || user.lastName;
    user.email = email || user.email;
    user.role = role || user.role;
    user.status = status || user.status;

    await user.save();
    res.status(200).json({ message: 'Profile updated successfully', user });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// DELETE USER PROFILE: Delete authenticated user's profile
exports.deleteUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await user.remove();
    res.status(200).json({ message: 'User profile deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// CHANGE PASSWORD: Change the password for the authenticated user
exports.changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordValid = await user.matchPassword(oldPassword);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Incorrect old password' });
    }

    user.password = newPassword;
    await user.save();
    res.status(200).json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// REFRESH TOKEN: Generate a new JWT token using refresh token
exports.refreshToken = (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'No refresh token provided' });
  }

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }

    const newToken = jwt.sign({ id: decoded.id, role: decoded.role }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(200).json({ message: 'Token refreshed', token: newToken });
  });
};

exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const resetToken = crypto.randomBytes(32).toString('hex');
      user.passwordResetToken = resetToken;
      user.passwordResetExpiration = Date.now() + 3600000; // 1 hour expiration
      await user.save();
  
      const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
  
      // Send reset link email (using nodemailer or any other service)
      const transporter = nodemailer.createTransport({ /* SMTP settings */ });
      await transporter.sendMail({
        to: user.email,
        subject: 'Password Reset Request',
        text: `Click the following link to reset your password: ${resetLink}`,
      });
  
      res.status(200).json({ message: 'Password reset link sent' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // VERIFY EMAIL: Verify email address using a token
  exports.verifyEmail = async (req, res) => {
    const { token } = req.params;
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      user.isEmailVerified = true;
      await user.save();
      res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
      res.status(400).json({ message: 'Invalid or expired verification token' });
    }
  };
  
  // RESEND VERIFICATION EMAIL: Resend email verification link
  exports.resendVerificationEmail = async (req, res) => {
    const { email } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user || user.isEmailVerified) {
        return res.status(400).json({ message: 'Email is already verified or user does not exist' });
      }
  
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      const verificationLink = `${process.env.FRONTEND_URL}/verify-email/${token}`;
  
      // Send verification email
      const transporter = nodemailer.createTransport({ /* SMTP settings */ });
      await transporter.sendMail({
        to: user.email,
        subject: 'Email Verification',
        text: `Click the following link to verify your email: ${verificationLink}`,
      });
  
      res.status(200).json({ message: 'Verification email resent' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // ENABLE 2FA: Enable Two-Factor Authentication for the user
  exports.enableTwoFactorAuth = async (req, res) => {
    const user = await User.findById(req.user.id);
  
    try {
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      user.is2FAEnabled = true;
      await user.save();
  
      // Implement actual 2FA setup here (e.g., sending a secret key via email or using an authenticator app)
  
      res.status(200).json({ message: 'Two-factor authentication enabled' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // DISABLE 2FA: Disable Two-Factor Authentication for the user
  exports.disableTwoFactorAuth = async (req, res) => {
    const user = await User.findById(req.user.id);
  
    try {
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      user.is2FAEnabled = false;
      await user.save();
  
      res.status(200).json({ message: 'Two-factor authentication disabled' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // VERIFY 2FA: Verify 2FA code provided by the user
  exports.verifyTwoFactorAuth = async (req, res) => {
    const { code } = req.body;  // The code is typically a one-time password (OTP)
  
    // Verify the code here using a 2FA service (like Google Authenticator, Authy, etc.)
    try {
      // Example validation (replace with actual verification logic)
      const isCodeValid = verify2FACode(code);  // Implement verify2FACode function
  
      if (!isCodeValid) {
        return res.status(400).json({ message: 'Invalid 2FA code' });
      }
  
      res.status(200).json({ message: '2FA verified successfully' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // CHECK EMAIL AVAILABILITY: Check if email is available for registration
  exports.checkEmailAvailability = async (req, res) => {
    const { email } = req.query;
  
    try {
      const user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ message: 'Email is already taken' });
      }
  
      res.status(200).json({ message: 'Email is available' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // Utility function to verify 2FA code (example, replace with actual logic)
  const verify2FACode = (code) => {
    // Example logic, replace with actual 2FA verification logic
    return code === '123456'; // Replace with actual OTP check logic
  };

  exports.changeEmail = async (req, res) => {
    const { newEmail } = req.body;
  
    try {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const token = jwt.sign({ id: user._id, newEmail }, process.env.JWT_SECRET, { expiresIn: '1h' });
      const confirmLink = `${process.env.FRONTEND_URL}/confirm-email-change/${token}`;
  
      // Send confirmation email
      const transporter = nodemailer.createTransport({ /* SMTP settings */ });
      await transporter.sendMail({
        to: newEmail,
        subject: 'Confirm Email Change',
        text: `Click the following link to confirm the email change: ${confirmLink}`,
      });
  
      res.status(200).json({ message: 'Email change requested. Please check your inbox.' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // CONFIRM EMAIL CHANGE: Confirm email change using the token
  exports.confirmEmailChange = async (req, res) => {
    const { token } = req.params;
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      user.email = decoded.newEmail;
      await user.save();
  
      res.status(200).json({ message: 'Email successfully changed' });
    } catch (error) {
      res.status(400).json({ message: 'Invalid or expired token' });
    }
  };
  
  // GET USER ROLES: Get available roles in the system
  exports.getUserRoles = async (req, res) => {
    const roles = ['user', 'admin', 'moderator']; // Example roles
    res.status(200).json({ roles });
  };
  
  // ASSIGN USER ROLE: Admin assigns a role to a user
  exports.assignUserRole = async (req, res) => {
    const { userId, role } = req.body;
  
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      user.role = role;
      await user.save();
  
      res.status(200).json({ message: `Role ${role} assigned to user` });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // REVOKE USER ROLE: Admin revokes a user's role
  exports.revokeUserRole = async (req, res) => {
    const { userId, role } = req.body;
  
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      if (user.role !== role) {
        return res.status(400).json({ message: `User does not have the ${role} role` });
      }
  
      user.role = null;  // Remove the role
      await user.save();
  
      res.status(200).json({ message: `Role ${role} revoked from user` });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // GENERATE API KEY: Generate an API key for the user
  exports.generateApiKey = async (req, res) => {
    const { userId } = req.body;
  
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const apiKey = crypto.randomBytes(32).toString('hex');
      user.apiKey = apiKey;
      await user.save();
  
      res.status(200).json({ message: 'API Key generated', apiKey });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // REVOKE API KEY: Revoke a user's API key
  exports.revokeApiKey = async (req, res) => {
    const { userId } = req.body;
  
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      user.apiKey = null;  // Remove the API key
      await user.save();
  
      res.status(200).json({ message: 'API Key revoked' });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // GET USER ACTIVITY LOGS: Get the user's activity logs
  exports.getUserActivityLogs = async (req, res) => {
    const { userId } = req.query;
  
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Example: Assuming you have an activity log model
      const activityLogs = []; // Replace with actual activity logs
  
      res.status(200).json({ activityLogs });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  };
  
  // SET PASSWORD STRENGTH RULES: Admin set global password strength rules
  exports.setPasswordStrength = async (req, res) => {
    const { minLength, requireUppercase, requireNumber } = req.body;
  
    // You can store this in a settings table or config file
    // Save the password strength rules globally here
  
    res.status(200).json({ message: 'Password strength rules updated' });
  };
  
  // CHECK PASSWORD STRENGTH: Check the password strength
  exports.checkPasswordStrength = (req, res) => {
    const { password } = req.body;
  
    // Password validation logic here
    const isValid = true; // Implement your password validation logic
    if (isValid) {
      res.status(200).json({ message: 'Password is strong' });
    } else {
      res.status(400).json({ message: 'Password is weak' });
    }
  };