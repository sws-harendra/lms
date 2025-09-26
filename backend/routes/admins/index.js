const express = require("express");
const router = express.Router();
const {
  getDashboardData,
} = require("../../controllers/admins/admin.controller");
const { authenticateToken } = require("../../middlewares/user.auth");
// router.get("/get-instructor-profile/:id", getInstructorProfile);
router.get("/dashboard", authenticateToken, getDashboardData);

module.exports = router;
