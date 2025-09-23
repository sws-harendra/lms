const express = require("express");
const router = express.Router();
const courseController = require("../controllers/course.controller");
const authorizePermission = require("../middlewares/authorization");
const { authenticateToken } = require("../middlewares/user.auth");
const { upload } = require("../helpers/multer");

// GET /api/courses?category=webdev&minRating=3.5&sortBy=rating&sortOrder=desc
router.get("/", courseController.getAllCourses);

router.get("/all-categories", courseController.getAllCategories);

router.get(
  "/my-enrolled-courses",
  authenticateToken,
  courseController.getMyEnrolledCourses
);
router.post(
  "/add-course",
  upload.fields([
    { name: "thumbnail", maxCount: 1 }, // for course thumbnail
    { name: "lessonVideos", maxCount: 20 }, // for lesson videos
  ]),
  authenticateToken,
  authorizePermission("create_course"),
  courseController.createCourse
);

// router.post(
//   "/add-course",
//   authenticateToken,
//   authorizePermission("create_course"),
//   courseController.createCourse
// );

router.get("/published", courseController.getPublishedCourses);
router.get("/slug/:slug", courseController.getCourseBySlug);
router.get("/:id", courseController.getCourseById);
router.put("/:id", courseController.updateCourse);
router.delete("/:id", courseController.deleteCourse);
router.patch("/toggle-publish/:id", courseController.togglePublishCourse);

module.exports = router;
