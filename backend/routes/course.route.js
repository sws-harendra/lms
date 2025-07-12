const express = require("express");
const router = express.Router();
const courses = require("../controllers/course.controller");
const { authenticateToken } = require("../../middlewares/user.auth");
const authorizePermission = require("../middlewares/authorization");

// GET /api/courses?category=webdev&minRating=3.5&sortBy=rating&sortOrder=desc
router.get("/", courses.getAllCourses);
router.post(
  "/",
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

router.router.module.exports = router;
