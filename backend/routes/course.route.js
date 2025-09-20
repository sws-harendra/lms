const express = require("express");
const router = express.Router();
const courseController = require("../controllers/course.controller");
const authorizePermission = require("../middlewares/authorization");
const { authenticateToken } = require("../middlewares/user.auth");

// GET /api/courses?category=webdev&minRating=3.5&sortBy=rating&sortOrder=desc
router.get("/", courseController.getAllCourses);
router.get(
  "/my-enrolled-courses",
  authenticateToken,
  courseController.getMyEnrolledCourses
);

router.post(
  "/add-course",
  authenticateToken,
  authorizePermission("create_course"),
  courseController.createCourse
);

router.post(
  "/add-course",
  authenticateToken,
  authorizePermission("create_course"),
  courseController.createCourse
);

router.get("/published", courseController.getPublishedCourses);
router.get("/slug/:slug", courseController.getCourseBySlug);
router.get("/:id", courseController.getCourseById);
router.put("/:id", courseController.updateCourse);
router.delete("/:id", courseController.deleteCourse);
router.patch("/toggle-publish/:id", courseController.togglePublishCourse);

module.exports = router;
