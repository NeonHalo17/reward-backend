const express = require('express');
const router = express.Router();
const { register, login, requestOTP, verifyOTPAndLogin, verifyEmail } = require('../controllers/authController');

router.post('/register', register);
router.post('/verify-email', verifyEmail);
router.post('/login', login);
router.post('/request-otp', requestOTP);
router.post('/verify-otp', verifyOTPAndLogin);

module.exports = router;
