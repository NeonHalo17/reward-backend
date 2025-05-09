const nodemailer = require('nodemailer');

// Store OTPs in memory with expiry (in production, use Redis or similar)
const otpStore = new Map();

// Generate a random 6-digit OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Configure nodemailer (replace with your email service details later)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your.email@gmail.com', // replace with your email
        pass: 'your-app-specific-password' // replace with your app password
    }
});

// Send OTP email
const sendOTPEmail = async (email, otp) => {
    const mailOptions = {
        from: 'your.email@gmail.com',
        to: email,
        subject: 'Login OTP',
        text: `Your OTP for login is: ${otp}. This OTP will expire in 5 minutes.`
    };

    await transporter.sendMail(mailOptions);
};

// Store OTP with 5-minute expiry
const storeOTP = (email, otp) => {
    otpStore.set(email, {
        otp,
        expiry: Date.now() + 5 * 60 * 1000 // 5 minutes
    });

    // Automatically delete OTP after 5 minutes
    setTimeout(() => {
        otpStore.delete(email);
    }, 5 * 60 * 1000);
};

// Verify OTP
const verifyOTP = (email, otp) => {
    const storedData = otpStore.get(email);
    if (!storedData) return false;

    if (Date.now() > storedData.expiry) {
        otpStore.delete(email);
        return false;
    }

    if (storedData.otp !== otp) return false;

    // Delete OTP after successful verification
    otpStore.delete(email);
    return true;
};

module.exports = {
    generateOTP,
    sendOTPEmail,
    storeOTP,
    verifyOTP
}; 