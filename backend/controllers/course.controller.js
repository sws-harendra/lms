const Course = require("../models/course.model");

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

    // Search by title, category, or tags
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
        { tags: { $regex: search, $options: "i" } },
      ];
    }

    // Optional Filters
    if (category) query.category = category;
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

    // Fetch courses
    const courses = await Course.find(query)
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    // Total count
    const total = await Course.countDocuments(query);

    res.status(200).json({
      data: courses,
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

const getCourseById = async (req, res) => {
  try {
    const course = await Course.findById(req.params.id).populate(
      "instructor",
      "name email"
    );
    if (!course) return res.status(404).json({ message: "Course not found" });
    res.json(course);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error fetching course", error: err.message });
  }
};

// Get a single course by slug
const getCourseBySlug = async (req, res) => {
  try {
    const course = await Course.findOne({ slug: req.params.slug }).populate(
      "instructor",
      "name email"
    );
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
    const course = await Course.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
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
    const course = await Course.findById(req.params.id);
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
    const courses = await Course.find({ isPublished: true }).populate(
      "instructor",
      "name email"
    );
    res.json(courses);
  } catch (err) {
    res.status(500).json({
      message: "Error fetching published courses",
      error: err.message,
    });
  }
};

const createCourse = async (req, res) => {const createCourse = async (req, res) => {
  try {
    const {
      title,
      slug,
      description,
      thumbnail,
      category,
      tags = [],
      price,
      discountPrice,
      isFree = false,
      isPublished = false,
      instructor,
      certificateEnabled = false,
      sections = [],
    } = req.body;

    // Validate mandatory fields
    if (
      !title ||
      !slug ||
      !description ||
      !thumbnail ||
      !category ||
      !price ||
      !instructor
    ) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Check for duplicate slug
    const existing = await Course.findOne({ slug });
    if (existing) {
      return res.status(409).json({ message: "Slug already exists" });
    }

    // Create the course
    const newCourse = await Course.create({
      title,
      slug,
      description,
      thumbnail,
      category,
      tags,
      price,
      discountPrice,
      isFree,
      isPublished,
      instructor,
      certificateEnabled,
      createdBy: req.user._id, // assumes user injected via auth middleware
      sections, // can include resources inline
    });

    res.status(201).json({ message: "Course created", course: newCourse });
  } catch (error) {
    console.error("Course creation failed:", error);
    res.status(500).json({ message: "Server error while creating course" });
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
};
