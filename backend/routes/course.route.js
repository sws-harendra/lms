const express = require("express");
const router = express.Router();
const courseController = require("../controllers/course.controller");
const authorizePermission = require("../middlewares/authorization");
const { authenticateToken } = require("../middlewares/user.auth");
const { upload } = require("../helpers/multer");
const {
  addOrUpdateReview,
  deleteReview,
  getCourseReviews,
  getMyReviewForCourse,
} = require("../controllers/review.controller");

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

router.get(
  "/get-all-courses-for-publisher",
  authenticateToken,
  courseController.getallcoursesforpublisher
);

router.get("/published", courseController.getPublishedCourses);
router.get("/slug/:slug", courseController.getCourseBySlug);
router.get("/:id", courseController.getCourseById);
router.put("/:id", courseController.updateCourse);
router.delete("/:id", courseController.deleteCourse);
router.patch("/toggle-publish/:id", courseController.togglePublishCourse);

// Reviews
// Public: list reviews for a course
router.get("/:courseId/reviews", getCourseReviews);
// Auth: get my review for a course
router.get(
  "/:courseId/my-review",
  authenticateToken,
  getMyReviewForCourse
);
// Auth: add or update my review
router.post(
  "/:courseId/reviews",
  authenticateToken,
  addOrUpdateReview
);
// Auth: delete my review
router.delete(
  "/:courseId/reviews",
  authenticateToken,
  deleteReview
);

module.exports = router;
