const express = require("express");
const router = express.Router();
const {
  getAdminDashboardData,
  getAllUsersWithRole,
  getUserByIdWithDetail,
  createUser,
} = require("../../controllers/admins/admin.controller");
const { authenticateToken } = require("../../middlewares/user.auth");
// router.get("/get-instructor-profile/:id", getInstructorProfile);
router.get("/dashboard", authenticateToken, getAdminDashboardData);
router.get("/users", authenticateToken, getAllUsersWithRole);
router.get("/users/:id", authenticateToken, getUserByIdWithDetail);
router.post("/users", authenticateToken, createUser);

module.exports = router;
