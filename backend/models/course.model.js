const mongoose = require("mongoose");
const resourceSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ["video", "pdf", "quiz", "assignment"],
    required: true,
  },
  title: String,
  url: String, // S3 or storage link
  duration: Number, // in minutes (for video)
  content: String, // for quiz instructions or assignment text
  isFree: {
    type: Boolean,
    default: false, // allow preview even if course is paid
  },
});

const sectionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  resources: [resourceSchema],
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
  },
  {
    timestamps: true,
  }
);
const Course = mongoose.model("Course", courseSchema);

module.exports = Course;
