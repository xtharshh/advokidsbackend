const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  points: { type: Number, default: 0 }
}, { timestamps: true });

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
