const mongoose = require("mongoose");

const lessonSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  videoUrl: {
    type: String,
    required: true,
  },
  duration: Number, // in minutes
  description: String,
  isFree: {
    type: Boolean,
    default: false, // allow preview even if course is paid
  },
  order: {
    type: Number,
    default: 0,
  },
});

const resourceSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ["video", "pdf", "quiz", "assignment", "text"],
    required: true,
  },
  title: {
    type: String,
    required: true,
    trim: true,
  },
  url: String, // S3 or storage link
  videoUrl: String, // for video resources
  duration: Number, // in minutes (for video)
  content: String, // for quiz instructions or assignment text
  isFree: {
    type: Boolean,
    default: false, // allow preview even if course is paid
  },
  order: {
    type: Number,
    default: 0,
  },
});

const sectionSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  description: String,
  order: {
    type: Number,
    default: 0,
  },
  lessons: [lessonSchema], // Added lessons array
  resources: [resourceSchema], // Keep resources for backward compatibility
});

const courseSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    slug: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    description: {
      type: String,
      required: true,
    },
    thumbnail: {
      type: String, // Image URL
      required: true,
    },
    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "CourseCategory",
      required: true,
    },
    tags: [String],

    price: {
      type: Number,
      required: true,
    },
    discountPrice: Number,

    isFree: {
      type: Boolean,
      default: false,
    },
    isPublished: {
      type: Boolean,
      default: false,
    },
    instructor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    sections: [sectionSchema],

    enrolledUsers: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    ],

    rating: {
      average: { type: Number, default: 0 },
      count: { type: Number, default: 0 },
    },

    certificateEnabled: {
      type: Boolean,
      default: false,
    },

    // Additional useful fields
    totalDuration: {
      type: Number,
      default: 0, // in minutes
    },

    level: {
      type: String,
      enum: ["beginner", "intermediate", "advanced"],
      default: "beginner",
    },

    language: {
      type: String,
      default: "English",
    },

    requirements: [String], // Prerequisites
    whatYouWillLearn: [String], // Learning outcomes
  },
  {
    timestamps: true,
  }
);

// Add index for better search performance
courseSchema.index({ title: "text", description: "text", tags: "text" });
courseSchema.index({ category: 1, isPublished: 1 });
courseSchema.index({ instructor: 1 });
courseSchema.index({ slug: 1 });

const Course = mongoose.model("Course", courseSchema);

module.exports = Course;
