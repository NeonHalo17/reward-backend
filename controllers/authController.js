const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateOTP, sendOTPEmail, storeOTP, verifyOTP } = require('../utils/emailUtils');

exports.register = async (req, res) => {
  const { firstName, lastName, email, mobile, password, dob, gender } = req.body;

  try {
    // Validate required fields
    if (!firstName || !lastName || !email || !mobile || !password) {
      return res.status(400).json({ 
        message: 'First name, last name, email, mobile, and password are required',
        receivedData: { firstName, lastName, email, mobile, password: '***' }
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user object
    const newUser = new User({
      firstName,
      lastName,
      email,
      mobile,
      password: hashedPassword,
      ...(dob && { dob: new Date(dob) }),
      ...(gender && { gender })
    });

    // Save user
    const savedUser = await newUser.save();
    
    res.status(201).json({ 
      message: 'User created successfully', 
      userId: savedUser.userId,
      email: savedUser.email
    });
  } catch (err) {
    console.error('Registration error:', err);
    if (err.name === 'ValidationError') {
      return res.status(400).json({ 
        message: 'Validation error', 
        errors: Object.values(err.errors).map(e => e.message)
      });
    }
    res.status(500).json({ 
      message: 'Server error',
      error: err.message 
    });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(200).json({
      token,
      user: {
        userId: user.userId,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        mobile: user.mobile,
        dob: user.dob,
        gender: user.gender
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// Request OTP for email login
exports.requestOTP = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found with this email' });
    }

    // Generate and store OTP
    const otp = generateOTP();
    storeOTP(email, otp);

    // Send OTP via email
    await sendOTPEmail(email, otp);

    res.status(200).json({ 
      message: 'OTP sent successfully',
      email: email // Return email for frontend reference
    });
  } catch (err) {
    console.error('OTP Request Error:', err);
    res.status(500).json({ message: 'Error sending OTP' });
  }
};

// Verify OTP and login
exports.verifyOTPAndLogin = async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP are required' });
  }

  try {
    // Verify OTP
    const isValid = verifyOTP(email, otp);
    if (!isValid) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    // Get user and generate token
    const user = await User.findOne({ email });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    res.status(200).json({
      token,
      user: {
        userId: user.userId,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        mobile: user.mobile,
        dob: user.dob,
        gender: user.gender
      }
    });
  } catch (err) {
    console.error('OTP Verification Error:', err);
    res.status(500).json({ message: 'Error verifying OTP' });
  }
};
