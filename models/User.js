const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  userId: { type: String, unique: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  mobile: { type: String, required: true },
  password: { type: String, required: true },
  dob: { type: Date },
  gender: { type: String },
  isVerified: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now }
});

// Create a pre-save middleware to generate userId
userSchema.pre('save', async function(next) {
  try {
    if (!this.userId) {
      const lastUser = await this.constructor.findOne({}, {}, { sort: { 'userId': -1 } });
      const lastNumber = lastUser ? parseInt(lastUser.userId.replace('USER', '')) : 0;
      this.userId = `USER${String(lastNumber + 1).padStart(4, '0')}`;
    }
    next();
  } catch (error) {
    next(error);
  }
});

module.exports = mongoose.model('User', userSchema);
