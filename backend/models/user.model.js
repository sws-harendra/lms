const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  phone: { type: String, unique: true, sparse: true },
  name: String,
  role: {
    type: String,
    // enum: ["user", "instructor", "admin"],
    default: "user", // 👈 default role
  },
  maxDevices: { type: Number, default: 2 },
  isVerified: Boolean,

  sessions: [
    {
      refreshToken: String,
      createdAt: { type: Date, default: Date.now },
      userAgent: String, // for browser/device info
      ip: String,
    },
  ],
});
const User = mongoose.model("User", userSchema);

module.exports = User;
