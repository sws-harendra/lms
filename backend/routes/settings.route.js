const express = require("express");
const router = express.Router();
const { getSettings, updateSettings } = require("../controllers/settings.controller");
const { authenticateToken } = require("../middlewares/user.auth");
// const authorizePermission = require("../middlewares/authorization");

// Public: read settings for frontend rendering
router.get("/", getSettings);

// Protected: update settings (limit to authenticated admins if you have permission middleware)
router.put("/", authenticateToken, /* authorizePermission("manage_settings"), */ updateSettings);

module.exports = router;
