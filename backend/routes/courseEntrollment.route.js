const express = require("express");
const router = express.Router();
const {
  enrollInCourse,
  completeEnrollment,
  getUserEnrollments,
  getEnrollmentDetails,
  markLessonCompleted,
  checkCourseAccess,
} = require("../controllers/courseEnrollment.controller");
const { authenticateToken } = require("../middlewares/user.auth");

// Enrollment routes
router.post("/enroll/:courseId", authenticateToken, enrollInCourse);
router.post("/complete", authenticateToken, completeEnrollment);
router.get("/my-courses", authenticateToken, getUserEnrollments);
router.get("/:enrollmentId", authenticateToken, getEnrollmentDetails);
router.post(
  "/:enrollmentId/complete-lesson",
  authenticateToken,
  markLessonCompleted
);
router.get("/access/:courseId", authenticateToken, checkCourseAccess);

module.exports = router;
