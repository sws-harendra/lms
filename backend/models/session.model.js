const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema({
  refreshToken: String,
  userAgent: String,
  ip: String,
  createdAt: {
    type: Date,
    default: Date.now,
    expires: "7d", // auto-remove old sessions
  },
});
module.exports = mongoose.model("Session", sessionSchema);
