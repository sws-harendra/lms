const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const User = require("../../models/user.model");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../../helpers/jwtToken");
const sendMail = require("../../helpers/mailsend");

// You'll need to implement this function for SMS OTP

// Phone OTP Registration/Login
const sendOtpToPhone = async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ message: "Phone required" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 min expiry

    let user = await User.findOne({ phone });
    if (!user) {
      // Register new phone user
      user = new User({
        phone,
        otpCode: otp,
        otpExpiry: expiry,
        isVerified: false,
        sessions: [],
        maxDevices: 5, // default value
      });
    } else {
      user.otpCode = otp;
      user.otpExpiry = expiry;
    }

    await user.save();
    await sendOtp(phone, otp);

    res.json({ message: "OTP sent to phone" });
  } catch (error) {
    console.error("Send OTP error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

const verifyPhoneOtp = async (req, res) => {
  try {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({ message: "Phone and OTP are required" });
    }

    const user = await User.findOne({ phone });

    if (!user || user.otpCode !== otp || user.otpExpiry < new Date()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.isVerified = true;
    user.otpCode = null;
    user.otpExpiry = null;

    // Enforce max devices
    if (user.sessions.length >= user.maxDevices) {
      // Remove oldest session
      user.sessions.shift();
    }

    const refreshToken = generateRefreshToken(user);
    const accessToken = generateAccessToken(user);

    user.sessions.push({
      refreshToken,
      userAgent: req.headers["user-agent"] || "Unknown",
      ip: req.ip || req.connection.remoteAddress || "Unknown",
      createdAt: new Date(),
    });

    await user.save();

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ message: "Login successful" });
  } catch (error) {
    console.error("Verify OTP error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Email Login
const emailloginController = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    if (!user.isVerified)
      return res.status(401).json({ message: "Email not verified" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid credentials" });

    // Enforce max devices
    if (user.sessions.length >= user.maxDevices) {
      // Remove oldest session
      //   user.sessions.shift();
      return res
        .status(403)
        .json({ message: "Device limit reached Logout from other devices" });
    }

    const refreshToken = generateRefreshToken(user);
    const accessToken = generateAccessToken(user);

    user.sessions.push({
      refreshToken,
      userAgent: req.headers["user-agent"] || "Unknown",
      ip: req.ip || req.connection.remoteAddress || "Unknown",
      createdAt: new Date(),
    });

    await user.save();

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ message: "Login successful" });
  } catch (error) {
    console.error("Email login error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Email Signup
const emailsignup = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check for existing email
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with "isVerified" flag
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      isVerified: false,
      sessions: [],
      maxDevices: 5,
    });

    await newUser.save();

    // Generate email verification token
    const verifyToken = jwt.sign(
      { id: newUser._id },
      process.env.AUTH_MAIL_SECRET,
      { expiresIn: "1h" }
    );
    console.log(`Verification token: ${verifyToken}`);

    const verifyLink = `${process.env.CLIENT_URL}/verify-account/${verifyToken}`;

    // Send verification email
    try {
      //   await sendMail(email, "Verify your email", "verifyEmail", {
      //     username: username,
      //     verifyLink: verifyLink,
      //   });
    } catch (mailError) {
      console.error("Email sending failed:", mailError);
      // Don't fail registration if email fails
    }

    res.status(201).json({
      message:
        "User registered successfully! Please check your email to verify your account.",
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Resend Email Verification
const resendEmailVerification = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.isVerified)
      return res.status(400).json({ message: "Email is already verified" });

    const verifyToken = jwt.sign(
      { id: user._id },
      process.env.AUTH_MAIL_SECRET,
      { expiresIn: "1h" }
    );
    const verifyLink = `${process.env.CLIENT_URL}/verify-account/${verifyToken}`;
    console.log(`Sending verification link to ${email}: ${verifyLink}`);

    try {
      //   await sendMail(email, "Resend Verification Email", "verifyEmail", {
      //     username: user.username,
      //     verifyLink,
      //   });
      res.json({ message: "Verification email resent successfully!" });
    } catch (mailError) {
      console.error("Email sending failed:", mailError);
      res.status(500).json({ message: "Failed to send verification email" });
    }
  } catch (error) {
    console.error("Resend verification error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Verify Email
const verifyEmail = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: "Token is required" });
    }

    const decoded = jwt.verify(token, process.env.AUTH_MAIL_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res
        .status(400)
        .json({ message: "Invalid token or user not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "Email is already verified" });
    }

    user.isVerified = true;
    await user.save();

    res.status(200).json({ message: "Email verified successfully!" });
  } catch (error) {
    console.error("Email verification error:", error);
    if (error.name === "JsonWebTokenError") {
      return res.status(400).json({ message: "Invalid token" });
    }
    if (error.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Token expired" });
    }
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Resend OTP to Phone
const resendOtpToPhone = async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ message: "Phone is required" });

    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 min expiry

    user.otpCode = otp;
    user.otpExpiry = expiry;
    await user.save();

    await sendOtp(phone, otp);

    res.json({ message: "OTP resent successfully to phone" });
  } catch (error) {
    console.error("Resend OTP error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Forgot Password
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const resetToken = jwt.sign(
      { id: user._id },
      process.env.AUTH_MAIL_SECRET,
      { expiresIn: "1h" }
    );

    const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

    try {
      await sendMail(email, "Password Reset Request", "resetPassword", {
        username: user.username,
        resetLink: resetLink,
      });
      res.json({ message: "Reset link sent to email" });
    } catch (mailError) {
      console.error("Email sending failed:", mailError);
      res.status(500).json({ message: "Failed to send reset email" });
    }
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Update Password
const updatepassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res
        .status(400)
        .json({ message: "Token and new password are required" });
    }

    const decoded = jwt.verify(token, process.env.AUTH_MAIL_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Clear all sessions to force re-login
    user.sessions = [];
    await user.save();

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Update password error:", error);
    if (error.name === "JsonWebTokenError") {
      return res.status(400).json({ message: "Invalid token" });
    }
    if (error.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Token expired" });
    }
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Get User Details
const userdetail = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -sessions -otpCode -otpExpiry"
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ user });
  } catch (error) {
    console.error("User detail error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Refresh Token
const refreshToken = async (req, res) => {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;

    if (!token)
      return res.status(401).json({ message: "No refresh token provided" });

    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user)
      return res
        .status(403)
        .json({ message: "Invalid token - user not found" });

    // Check if this token exists in user's session list
    const sessionMatch = user.sessions.find(
      (session) => session.refreshToken === token
    );

    if (!sessionMatch) {
      return res.status(403).json({ message: "Session not found or expired" });
    }

    const newAccessToken = generateAccessToken(user);

    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    return res.json({
      message: "Token refreshed successfully",
      accessToken: newAccessToken,
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    if (error.name === "JsonWebTokenError") {
      return res.status(403).json({ message: "Invalid token" });
    }
    if (error.name === "TokenExpiredError") {
      return res.status(403).json({ message: "Token expired" });
    }
    return res
      .status(500)
      .json({ message: "Server error", error: error.message });
  }
};

// Logout (clear session)
const logout = async (req, res) => {
  try {
    const token = req.cookies.refreshToken || req.body.refreshToken;

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
      const user = await User.findById(decoded.id);

      if (user) {
        // Remove this session from user's sessions
        user.sessions = user.sessions.filter(
          (session) => session.refreshToken !== token
        );
        await user.save();
      }
    }

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.json({ message: "Logged out successfully" });
  }
};

module.exports = {
  emailloginController,
  emailsignup,
  verifyEmail,
  userdetail,
  forgotPassword,
  updatepassword,
  refreshToken,
  sendOtpToPhone,
  verifyPhoneOtp,
  resendEmailVerification,
  resendOtpToPhone,
  logout,
};
