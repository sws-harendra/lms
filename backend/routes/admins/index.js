const express = require("express");
const router = express.Router();
const {
  getAdminDashboardData,
  getAllUsersWithRole,
  getUserByIdWithDetail,
  createUser,
  updateUserByAdmin,
  deleteUserByAdmin,
} = require("../../controllers/admins/admin.controller");
const { authenticateToken } = require("../../middlewares/user.auth");
// router.get("/get-instructor-profile/:id", getInstructorProfile);
router.get("/dashboard", authenticateToken, getAdminDashboardData);
router.get("/users", authenticateToken, getAllUsersWithRole);
router.get("/users/:id", authenticateToken, getUserByIdWithDetail);
router.post("/users", authenticateToken, createUser);
router.put("/users/:id", authenticateToken, updateUserByAdmin);
router.delete("/users/:id", authenticateToken, deleteUserByAdmin);

module.exports = router;
