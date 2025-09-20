const Enrollment = require("../models/enrollment.model");
const Course = require("../models/course.model");
const Payment = require("../models/payment.model");
const User = require("../models/user.model");

// Enroll in a course
const enrollInCourse = async (req, res) => {
  try {
    const { courseId } = req.params;
    const { paymentMethod, transactionId, paymentStatus } = req.body;
    const userId = req.user.id;

    // 1. Check if course exists and is published
    const course = await Course.findById(courseId);
    if (!course || !course.isPublished) {
      return res
        .status(404)
        .json({ message: "Course not found or not available" });
    }

    // 2. Check if user already enrolled
    const existingEnrollment = await Enrollment.findOne({
      user: userId,
      course: courseId,
    });
    if (existingEnrollment) {
      return res
        .status(400)
        .json({ message: "Already enrolled in this course" });
    }

    // 3. Handle free courses (direct enrollment)
    if (course.isFree || course.price === 0) {
      const enrollment = new Enrollment({
        user: userId,
        course: courseId,
        payment: {
          amount: 0,
          paymentMethod: "free",
          paymentStatus: "completed",
          paymentDate: new Date(),
        },
      });

      await enrollment.save();
      await Course.findByIdAndUpdate(courseId, {
        $addToSet: { enrolledUsers: userId },
      });

      return res.status(201).json({
        message: "Successfully enrolled in free course",
        enrollment,
      });
    }

    // 4. Paid courses → Check if payment is completed
    if (!transactionId || paymentStatus !== "completed") {
      // If payment not completed, create a pending payment record and return
      const pendingPayment = new Payment({
        user: userId,
        course: courseId,
        amount: course.discountPrice || course.price,
        paymentMethod: paymentMethod || "stripe",
        status: "pending",
      });

      await pendingPayment.save();

      return res.status(200).json({
        message: "Payment initiated. Complete the payment to get access.",
        paymentId: pendingPayment._id,
        amount: pendingPayment.amount,
      });
    }

    // 5. Payment completed → Save payment + enrollment
    const payment = new Payment({
      user: userId,
      course: courseId,
      amount: course.discountPrice || course.price,
      paymentMethod: paymentMethod || "stripe",
      status: "completed",
      transactionId,
      metadata: req.body.metadata || {},
    });

    await payment.save();

    const enrollment = new Enrollment({
      user: userId,
      course: courseId,
      payment: {
        transactionId,
        amount: payment.amount,
        currency: payment.currency,
        paymentMethod: payment.paymentMethod,
        paymentStatus: "completed",
        paymentDate: new Date(),
      },
    });

    await enrollment.save();

    // Link payment <-> enrollment
    payment.enrollment = enrollment._id;
    await payment.save();

    // Add user to course enrolledUsers
    await Course.findByIdAndUpdate(courseId, {
      $addToSet: { enrolledUsers: userId },
    });

    res.status(201).json({
      message: "Enrollment completed successfully",
      enrollment,
    });
  } catch (error) {
    console.error("Unified enrollment error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Complete enrollment after successful payment
// const completeEnrollment = async (req, res) => {
//   try {
//     const { paymentId, transactionId } = req.body;
//     const userId = req.user.id;

//     // Find and update payment
//     const payment = await Payment.findOneAndUpdate(
//       { _id: paymentId, user: userId, status: "pending" },
//       {
//         status: "completed",
//         transactionId,
//         metadata: req.body.metadata || {},
//       },
//       { new: true }
//     );

//     if (!payment) {
//       return res
//         .status(404)
//         .json({ message: "Payment not found or already processed" });
//     }

//     // Create enrollment
//     const enrollment = new Enrollment({
//       user: userId,
//       course: payment.course,
//       payment: {
//         transactionId,
//         amount: payment.amount,
//         currency: payment.currency,
//         paymentMethod: payment.paymentMethod,
//         paymentStatus: "completed",
//         paymentDate: new Date(),
//       },
//     });

//     await enrollment.save();

//     // Update payment with enrollment reference
//     payment.enrollment = enrollment._id;
//     await payment.save();

//     // Add user to course's enrolled users
//     await Course.findByIdAndUpdate(payment.course, {
//       $addToSet: { enrolledUsers: userId },
//     });

//     res.status(201).json({
//       message: "Enrollment completed successfully",
//       enrollment,
//     });
//   } catch (error) {
//     console.log("-->Complete enrollment error:", error);
//     res.status(500).json({ message: "Server error", error: error.message });
//   }
// };

// Get user's enrollments
const getUserEnrollments = async (req, res) => {
  try {
    const userId = req.user.id;
    const { status, page = 1, limit = 10 } = req.query;

    const query = { user: userId };
    if (status) query.status = status;

    const enrollments = await Enrollment.find(query)
      .populate({
        path: "course",
        select:
          "title slug thumbnail category price discountPrice level totalDuration",
        populate: {
          path: "category",
          select: "name slug",
        },
      })
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Enrollment.countDocuments(query);

    res.status(200).json({
      enrollments,
      pagination: {
        current: page,
        pages: Math.ceil(total / limit),
        total,
      },
    });
  } catch (error) {
    console.error("Get enrollments error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Get specific enrollment details
const getEnrollmentDetails = async (req, res) => {
  try {
    const { enrollmentId } = req.params;
    const userId = req.user.id;

    const enrollment = await Enrollment.findOne({
      _id: enrollmentId,
      user: userId,
    }).populate({
      path: "course",
      populate: {
        path: "category instructor",
        select: "name email",
      },
    });

    if (!enrollment) {
      return res.status(404).json({ message: "Enrollment not found" });
    }

    // Calculate current progress
    await enrollment.calculateProgress();
    await enrollment.save();

    res.status(200).json({ enrollment });
  } catch (error) {
    console.error("Get enrollment details error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Mark lesson as completed
const markLessonCompleted = async (req, res) => {
  try {
    const { enrollmentId } = req.params;
    const { sectionId, lessonId, watchTime } = req.body;
    const userId = req.user.id;

    const enrollment = await Enrollment.findOne({
      _id: enrollmentId,
      user: userId,
      status: "active",
    });

    if (!enrollment) {
      return res.status(404).json({ message: "Active enrollment not found" });
    }

    enrollment.markLessonCompleted(sectionId, lessonId, watchTime);
    const progress = await enrollment.calculateProgress();

    // Check if course is completed
    if (progress === 100 && enrollment.status === "active") {
      enrollment.status = "completed";
    }

    await enrollment.save();

    res.status(200).json({
      message: "Lesson marked as completed",
      progress: enrollment.progress,
    });
  } catch (error) {
    console.error("Mark lesson completed error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Check if user has access to course
const checkCourseAccess = async (req, res) => {
  try {
    const { courseId } = req.params;
    const userId = req.user.id;

    const enrollment = await Enrollment.findOne({
      user: userId,
      course: courseId,
      status: { $in: ["active", "completed"] },
    });

    const hasAccess = !!enrollment;

    res.status(200).json({
      hasAccess,
      enrollment: hasAccess ? enrollment : null,
    });
  } catch (error) {
    console.error("Check course access error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

module.exports = {
  enrollInCourse,
  // completeEnrollment,
  getUserEnrollments,
  getEnrollmentDetails,
  markLessonCompleted,
  checkCourseAccess,
};
