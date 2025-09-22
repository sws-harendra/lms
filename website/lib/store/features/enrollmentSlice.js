import { enrollmentService } from "@/services/user/enrollment.service";
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";

// Async thunks
export const enrollInCourse = createAsyncThunk(
  "enrollment/enrollInCourse",
  async ({ courseId, paymentData }, { rejectWithValue }) => {
    try {
      const response = await enrollmentService.enrollInCourse(
        courseId,
        paymentData
      );
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to enroll in course"
      );
    }
  }
);

export const completeEnrollment = createAsyncThunk(
  "enrollment/completeEnrollment",
  async (enrollmentData, { rejectWithValue }) => {
    try {
      const response = await enrollmentService.completeEnrollment(
        enrollmentData
      );
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to complete enrollment"
      );
    }
  }
);

export const getUserEnrollments = createAsyncThunk(
  "enrollment/getUserEnrollments",
  async (params = {}, { rejectWithValue }) => {
    try {
      const response = await enrollmentService.getUserEnrollments(params);
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to fetch enrollments"
      );
    }
  }
);

export const getEnrollmentDetails = createAsyncThunk(
  "enrollment/getEnrollmentDetails",
  async (enrollmentId, { rejectWithValue }) => {
    try {
      const response = await enrollmentService.getEnrollmentDetails(
        enrollmentId
      );
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to fetch enrollment details"
      );
    }
  }
);

export const markLessonCompleted = createAsyncThunk(
  "enrollment/markLessonCompleted",
  async ({ enrollmentId, lessonData }, { rejectWithValue }) => {
    console.log(enrollmentId, lessonData);
    try {
      const response = await enrollmentService.markLessonCompleted(
        enrollmentId,
        lessonData
      );
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to mark lesson as completed"
      );
    }
  }
);

export const checkCourseAccess = createAsyncThunk(
  "enrollment/checkCourseAccess",
  async (courseId, { rejectWithValue }) => {
    try {
      const response = await enrollmentService.checkCourseAccess(courseId);
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to check course access"
      );
    }
  }
);

const initialState = {
  enrollments: [],
  currentEnrollment: null,
  courseAccess: null,
  status: "idle", // 'idle' | 'loading' | 'succeeded' | 'failed'
  enrollStatus: "idle",
  accessStatus: "idle",
  lessonStatus: "idle",
  error: null,
  pagination: {
    current: 1,
    pages: 1,
    total: 0,
  },
};

const enrollmentSlice = createSlice({
  name: "enrollment",
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    clearCurrentEnrollment: (state) => {
      state.currentEnrollment = null;
    },
    clearCourseAccess: (state) => {
      state.courseAccess = null;
    },
    resetEnrollmentState: (state) => {
      state.status = "idle";
      state.enrollStatus = "idle";
      state.accessStatus = "idle";
      state.lessonStatus = "idle";
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      // Enroll in Course
      .addCase(enrollInCourse.pending, (state) => {
        state.enrollStatus = "loading";
        state.error = null;
      })
      .addCase(enrollInCourse.fulfilled, (state, action) => {
        state.enrollStatus = "succeeded";
        state.error = null;
        // If it's a free course, add to enrollments
        if (action.payload.enrollment) {
          state.enrollments.unshift(action.payload.enrollment);
        }
      })
      .addCase(enrollInCourse.rejected, (state, action) => {
        state.enrollStatus = "failed";
        state.error = action.payload;
      })

      // Complete Enrollment
      .addCase(completeEnrollment.pending, (state) => {
        state.enrollStatus = "loading";
        state.error = null;
      })
      .addCase(completeEnrollment.fulfilled, (state, action) => {
        state.enrollStatus = "succeeded";
        state.enrollments.unshift(action.payload.enrollment);
        state.error = null;
      })
      .addCase(completeEnrollment.rejected, (state, action) => {
        state.enrollStatus = "failed";
        state.error = action.payload;
      })

      // Get User Enrollments
      .addCase(getUserEnrollments.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getUserEnrollments.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.enrollments = action.payload.enrollments;
        state.pagination = action.payload.pagination;
        state.error = null;
      })
      .addCase(getUserEnrollments.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
      })

      // Get Enrollment Details
      .addCase(getEnrollmentDetails.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getEnrollmentDetails.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.currentEnrollment = action.payload.enrollment;
        state.error = null;
      })
      .addCase(getEnrollmentDetails.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
      })

      // Mark Lesson Completed
      .addCase(markLessonCompleted.pending, (state) => {
        state.lessonStatus = "loading";
        state.error = null;
      })
      .addCase(markLessonCompleted.fulfilled, (state, action) => {
        state.lessonStatus = "succeeded";
        if (state.currentEnrollment) {
          state.currentEnrollment.progress = action.payload.progress;
        }
        state.error = null;
      })
      .addCase(markLessonCompleted.rejected, (state, action) => {
        state.lessonStatus = "failed";
        state.error = action.payload;
      })

      // Check Course Access
      .addCase(checkCourseAccess.pending, (state) => {
        state.accessStatus = "loading";
        state.error = null;
      })
      .addCase(checkCourseAccess.fulfilled, (state, action) => {
        state.accessStatus = "succeeded";
        state.courseAccess = action.payload;
        state.error = null;
      })
      .addCase(checkCourseAccess.rejected, (state, action) => {
        state.accessStatus = "failed";
        state.error = action.payload;
      });
  },
});

export const {
  clearError,
  clearCurrentEnrollment,
  clearCourseAccess,
  resetEnrollmentState,
} = enrollmentSlice.actions;

export default enrollmentSlice.reducer;
