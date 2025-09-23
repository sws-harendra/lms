const Course = require("../models/course.model");
const CourseCategory = require("../models/courseCategory.model");
const mongoose = require("mongoose");
const Enrollment = require("../models/enrollment.model");
const path = require("path");

const getAllCourses = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = "",
      category,
      isFree,
      isPublished,
      sortBy = "createdAt", // now can also be "rating"
      sortOrder = "desc",
      minRating = 0,
      maxRating = 5,
    } = req.query;

    const query = {};

    // Search by title, description, or tags
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { tags: { $regex: search, $options: "i" } },
      ];
    }

    // Optional Filters
    if (category) {
      // Check if category is ObjectId or slug/name
      if (mongoose.Types.ObjectId.isValid(category)) {
        query.category = category;
      } else {
        // Find category by slug or name
        const categoryDoc = await CourseCategory.findOne({
          $or: [
            { slug: category },
            { name: { $regex: category, $options: "i" } },
          ],
        });
        if (categoryDoc) {
          query.category = categoryDoc._id;
        }
      }
    }

    if (isFree !== undefined) query.isFree = isFree === "true";
    if (isPublished !== undefined) query.isPublished = isPublished === "true";

    // Rating filter
    query["rating.average"] = {
      $gte: parseFloat(minRating),
      $lte: parseFloat(maxRating),
    };

    // Sorting
    const sort = {};
    if (sortBy === "rating") {
      sort["rating.average"] = sortOrder === "asc" ? 1 : -1;
    } else {
      sort[sortBy] = sortOrder === "asc" ? 1 : -1;
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Fetch courses with populated category
    const courses = await Course.find(query)
      .select(
        "title slug description thumbnail price discountPrice isFree rating category instructor"
      )

      .populate("category", "name slug icon")
      .populate("instructor", "name email")
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    // Total count
    const total = await Course.countDocuments(query);

    res.status(200).json({
      courses: courses,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error("Error fetching courses:", err);
    res.status(500).json({ error: "Server error while fetching courses" });
  }
};

const getMyEnrolledCourses = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = "",
      category,
      sortBy = "createdAt", // course createdAt
      sortOrder = "desc",
    } = req.query;

    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized: user not found" });
    }

    // Pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Enrollment query (only user’s enrollments)
    const enrollmentQuery = { user: userId };

    // Populate course with filters
    let courseMatch = {};

    // Search by title/description/tags
    if (search) {
      courseMatch.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { tags: { $regex: search, $options: "i" } },
      ];
    }

    // Category filter
    if (category) {
      if (mongoose.Types.ObjectId.isValid(category)) {
        courseMatch.category = category;
      } else {
        const categoryDoc = await CourseCategory.findOne({
          $or: [
            { slug: category },
            { name: { $regex: category, $options: "i" } },
          ],
        });
        if (categoryDoc) {
          courseMatch.category = categoryDoc._id;
        }
      }
    }

    // Sorting
    const sort = {};
    if (sortBy === "rating") {
      sort["course.rating.average"] = sortOrder === "asc" ? 1 : -1;
    } else {
      sort[`course.${sortBy}`] = sortOrder === "asc" ? 1 : -1;
    }

    // Get enrollments with populated courses
    const enrollments = await Enrollment.find(enrollmentQuery)
      .populate({
        path: "course",
        match: courseMatch, // apply filters inside course
        select:
          "title slug description thumbnail price discountPrice isFree rating category instructor",
        populate: [
          { path: "category", select: "name slug icon" },
          { path: "instructor", select: "name email" },
        ],
      })
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    // Filter out enrollments where course didn't match filters
    const validEnrollments = enrollments.filter((e) => e.course);

    // Total count
    const total = await Enrollment.countDocuments(enrollmentQuery);

    res.status(200).json({
      enrolledCourses: validEnrollments,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    console.error("Error fetching enrolled courses:", err);
    res
      .status(500)
      .json({ error: "Server error while fetching enrolled courses" });
  }
};

const getCourseById = async (req, res) => {
  try {
    const course = await Course.findById(req.params.id)
      .populate("instructor", "name email")
      .populate("category", "name slug icon");

    if (!course) return res.status(404).json({ message: "Course not found" });
    res.json({ course });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching course", error: err.message });
  }
};

// Get a single course by slug
const getCourseBySlug = async (req, res) => {
  try {
    const course = await Course.findOne({ slug: req.params.slug })
      .populate("instructor", "name email")
      .populate("category", "name slug icon");

    if (!course) return res.status(404).json({ message: "Course not found" });
    res.json(course);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching course", error: err.message });
  }
};

// Update a course
const updateCourse = async (req, res) => {
  try {
    // If category is being updated, validate it exists
    if (req.body.category) {
      const categoryExists = await CourseCategory.findById(req.body.category);
      if (!categoryExists) {
        return res.status(400).json({ message: "Invalid category ID" });
      }
    }

    const course = await Course.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    })
      .populate("instructor", "name email")
      .populate("category", "name slug icon");

    if (!course) return res.status(404).json({ message: "Course not found" });
    res.json({ message: "Course updated", course });
  } catch (err) {
    res
      .status(400)
      .json({ message: "Error updating course", error: err.message });
  }
};

// Delete a course
const deleteCourse = async (req, res) => {
  try {
    const course = await Course.findByIdAndDelete(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });
    res.json({ message: "Course deleted" });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error deleting course", error: err.message });
  }
};

// Toggle publish/unpublish
const togglePublishCourse = async (req, res) => {
  try {
    const course = await Course.findById(req.params.id).populate(
      "category",
      "name slug icon"
    );

    if (!course) return res.status(404).json({ message: "Course not found" });

    course.isPublished = !course.isPublished;
    await course.save();

    res.json({
      message: `Course ${course.isPublished ? "published" : "unpublished"}`,
      course,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error toggling publish state", error: err.message });
  }
};

// Get published courses only (for students / landing page)
const getPublishedCourses = async (req, res) => {
  try {
    const courses = await Course.find({ isPublished: true })
      .populate("instructor", "name email")
      .populate("category", "name slug icon");

    res.json(courses);
  } catch (err) {
    res.status(500).json({
      message: "Error fetching published courses",
      error: err.message,
    });
  }
};

const createCourse = async (req, res) => {
  try {
    const {
      title,
      slug,
      description,
      category,
      tags = [],
      price,
      discountPrice,
      isFree = false,
      isPublished = false,
      instructor,
      certificateEnabled = false,
      level = "beginner",
      language = "English",
      requirements = [],
      whatYouWillLearn = [],
    } = req.body;

    // Validate required fields
    if (!title || !slug || !description || !category || price === undefined) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Validate category exists
    const categoryExists = await CourseCategory.findById(category);
    if (!categoryExists)
      return res.status(400).json({ message: "Invalid category ID" });

    // Check for duplicate slug
    const existing = await Course.findOne({ slug });
    if (existing)
      return res.status(409).json({ message: "Slug already exists" });

    // Parse JSON fields (sections)
    let sectionsData = [];
    try {
      sectionsData =
        typeof req.body.sections === "string"
          ? JSON.parse(req.body.sections)
          : req.body.sections || [];
    } catch (err) {
      return res.status(400).json({ message: "Invalid sections JSON" });
    }

    // Handle thumbnail upload
    let thumbnailUrl = req.body.thumbnail || "";
    if (req.files?.thumbnail?.[0]) {
      thumbnailUrl = `/uploads/${req.files.thumbnail[0].filename}`;
    }

    // Handle lesson video uploads
    const uploadedFiles = req.files?.lessonVideos || [];
    let fileIndex = 0;

    const processedSections = sectionsData.map((section) => {
      const lessons = section.lessons.map((lesson) => {
        // Use uploaded file if no videoUrl provided
        if (!lesson.videoUrl && uploadedFiles[fileIndex]) {
          lesson.videoUrl = `/uploads/${uploadedFiles[fileIndex].filename}`;
          fileIndex++;
        }
        return lesson;
      });
      return { ...section, lessons };
    });

    // Calculate total duration
    let totalDuration = 0;
    processedSections.forEach((section) => {
      section.lessons.forEach((lesson) => {
        if (lesson.duration) totalDuration += lesson.duration;
      });
    });

    // Create the course
    const newCourse = await Course.create({
      title,
      slug,
      description,
      thumbnail: thumbnailUrl,
      category,
      tags,
      price,
      discountPrice,
      isFree,
      isPublished,
      instructor: instructor || req.user?.id,
      certificateEnabled,
      createdBy: req.user?.id || instructor,
      sections: processedSections,
      totalDuration,
      level,
      language,
      requirements,
      whatYouWillLearn,
    });

    // Populate for response
    const populatedCourse = await Course.findById(newCourse._id)
      .populate("instructor", "name email")
      .populate("category", "name slug icon");

    res.status(201).json({
      message: "Course created successfully",
      course: populatedCourse,
    });
  } catch (error) {
    console.error("Course creation failed:", error);

    // Validation errors
    if (error.name === "ValidationError") {
      const errors = Object.values(error.errors).map((err) => err.message);
      return res.status(400).json({ message: "Validation error", errors });
    }

    res.status(500).json({ message: "Server error while creating course" });
  }
};

// Get courses by category
const getCoursesByCategory = async (req, res) => {
  try {
    const { categoryId } = req.params;
    const { page = 1, limit = 10 } = req.query;

    // Validate category exists
    const category = await CourseCategory.findById(categoryId);
    if (!category) {
      return res.status(404).json({ message: "Category not found" });
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const courses = await Course.find({
      category: categoryId,
      isPublished: true,
    })
      .populate("instructor", "name email")
      .populate("category", "name slug icon")
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

    const total = await Course.countDocuments({
      category: categoryId,
      isPublished: true,
    });

    res.json({
      data: courses,
      category: category,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err) {
    res.status(500).json({
      message: "Error fetching courses by category",
      error: err.message,
    });
  }
};

const getAllCategories = async (req, res) => {
  try {
    const categoryList = await CourseCategory.find().sort({ name: 1 });
    res.status(200).json({ categories: categoryList });
  } catch (err) {
    console.error("Error fetching categories:", err);
    res.status(500).json({ error: "Server error while fetching categories" });
  }
};
module.exports = {
  getAllCourses,
  createCourse,
  getCourseById,
  getCourseBySlug,
  updateCourse,
  deleteCourse,
  togglePublishCourse,
  getPublishedCourses,
  getCoursesByCategory,
  getMyEnrolledCourses,
  getAllCategories,
};
