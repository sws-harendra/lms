const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: String,
  name: String,
  password: String,
  phone: { type: String, unique: true, sparse: true },
  name: String,
  role: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Role",
    default: null, // We'll set this programmatically
  },
  maxDevices: { type: Number, default: 2 },
  isVerified: Boolean,
  // Add OTP fields that are being used in auth controller
  otpCode: String,
  otpExpiry: Date,

  sessions: [
    {
      refreshToken: String,
      createdAt: { type: Date, default: Date.now },
      userAgent: String, // for browser/device info
      ip: String,
    },
  ],
});

// Pre-save middleware to set default role if none provided
userSchema.pre("save", async function (next) {
  if (!this.role) {
    const Role = require("./role.model");
    const defaultRole = await Role.findOne({ name: "user" });
    if (defaultRole) {
      this.role = defaultRole._id;
    }
  }
  next();
});

const User = mongoose.model("User", userSchema);

module.exports = User;
