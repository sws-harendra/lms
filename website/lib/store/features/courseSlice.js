import { courseService } from "@/services/course.service";
import { createSlice, createAsyncThunk } from "@reduxjs/toolkit";

// Async thunks

export const getAllCourses = createAsyncThunk(
  "course/getAllCourses",
  async (_, { rejectWithValue }) => {
    try {
      const response = await courseService.getAllCourses();
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to fetch courses"
      );
    }
  }
);

export const getAllCategories = createAsyncThunk(
  "course/getAllCategories",
  async (_, { rejectWithValue }) => {
    try {
      const response = await courseService.getAllCategories();
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to fetch courses"
      );
    }
  }
);

export const getMyEnrolledCourses = createAsyncThunk(
  "course/getMyEnrolledCourses",
  async (_, { rejectWithValue }) => {
    try {
      const response = await courseService.getEnrolledCourses();
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to fetch courses"
      );
    }
  }
);
export const createCourse = createAsyncThunk(
  "course/createCourse",
  async (formData, { rejectWithValue }) => {
    try {
      const response = await courseService.createCourse(formData);
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to create course"
      );
    }
  }
);

export const getPublishedCourses = createAsyncThunk(
  "course/getPublishedCourses",
  async (_, { rejectWithValue }) => {
    try {
      const response = await courseService.getPublishedCourses();
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to fetch published courses"
      );
    }
  }
);

export const getCourseBySlug = createAsyncThunk(
  "course/getCourseBySlug",
  async (slug, { rejectWithValue }) => {
    try {
      const response = await courseService.getCourseBySlug(slug);
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to fetch course"
      );
    }
  }
);

export const getCourseById = createAsyncThunk(
  "course/getCourseById",
  async (id, { rejectWithValue }) => {
    try {
      const response = await courseService.getCourseById(id);
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to fetch course"
      );
    }
  }
);

export const updateCourse = createAsyncThunk(
  "course/updateCourse",
  async ({ id, courseData }, { rejectWithValue }) => {
    try {
      const response = await courseService.updateCourse(id, courseData);
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to update course"
      );
    }
  }
);

export const deleteCourse = createAsyncThunk(
  "course/deleteCourse",
  async (id, { rejectWithValue }) => {
    try {
      const response = await courseService.deleteCourse(id);
      return { ...response, deletedId: id };
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message || "Failed to delete course"
      );
    }
  }
);

export const togglePublishCourse = createAsyncThunk(
  "course/togglePublishCourse",
  async (id, { rejectWithValue }) => {
    try {
      const response = await courseService.togglePublishCourse(id);
      return response;
    } catch (error) {
      return rejectWithValue(
        error.response?.data?.message ||
          "Failed to toggle course publish status"
      );
    }
  }
);

const initialState = {
  courses: [],
  myEnrolledcourses: [],
  publishedCourses: [],
  currentCourse: null,
  categories: [],
  status: "idle", // 'idle' | 'loading' | 'succeeded' | 'failed'
  createStatus: "idle",
  updateStatus: "idle",
  deleteStatus: "idle",
  publishStatus: "idle",
  error: null,
  totalCourses: 0,
  pagination: {
    currentPage: 1,
    totalPages: 1,
    hasNext: false,
    hasPrev: false,
  },
};

const courseSlice = createSlice({
  name: "course",
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
    },
    clearCurrentCourse: (state) => {
      state.currentCourse = null;
    },
    resetCourseState: (state) => {
      state.status = "idle";
      state.createStatus = "idle";
      state.updateStatus = "idle";
      state.deleteStatus = "idle";
      state.publishStatus = "idle";
      state.error = null;
    },
    setPagination: (state, action) => {
      state.pagination = { ...state.pagination, ...action.payload };
    },
  },
  extraReducers: (builder) => {
    builder
      // Get All Courses
      .addCase(getAllCourses.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getAllCourses.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.courses = action.payload.courses || action.payload;
        state.totalCourses = action.payload.total || action.payload.length;
        if (action.payload.pagination) {
          state.pagination = action.payload.pagination;
        }
        state.error = null;
      })
      .addCase(getAllCourses.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
      })

      // Create Course
      .addCase(createCourse.pending, (state) => {
        state.createStatus = "loading";
        state.error = null;
      })
      .addCase(createCourse.fulfilled, (state, action) => {
        state.createStatus = "succeeded";
        state.courses.unshift(action.payload.course || action.payload);
        state.totalCourses += 1;
        state.error = null;
      })
      .addCase(createCourse.rejected, (state, action) => {
        state.createStatus = "failed";
        state.error = action.payload;
      })
      .addCase(getMyEnrolledCourses.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getMyEnrolledCourses.fulfilled, (state, action) => {
        state.status = "succeeded";

        // store the array of enrolled courses
        state.myEnrolledcourses = action.payload.enrolledCourses || [];

        // store pagination info
        state.pagination = {
          currentPage: action.payload.pagination?.page || 1,
          totalPages: action.payload.pagination?.totalPages || 1,
          hasNext:
            action.payload.pagination?.page <
            action.payload.pagination?.totalPages,
          hasPrev: action.payload.pagination?.page > 1,
        };

        state.error = null;
      })

      .addCase(getMyEnrolledCourses.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
      })
      // Get Published Courses
      .addCase(getPublishedCourses.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getPublishedCourses.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.publishedCourses = action.payload.courses || action.payload;
        state.error = null;
      })
      .addCase(getPublishedCourses.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
      })

      // Get Course by Slug
      .addCase(getCourseBySlug.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getCourseBySlug.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.currentCourse = action.payload.course || action.payload;
        state.error = null;
      })
      .addCase(getCourseBySlug.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
        state.currentCourse = null;
      })

      // Get Course by ID
      .addCase(getCourseById.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })
      .addCase(getCourseById.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.currentCourse = action.payload.course || action.payload;
        state.error = null;
      })
      .addCase(getCourseById.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
        state.currentCourse = null;
      })

      // Update Course
      .addCase(updateCourse.pending, (state) => {
        state.updateStatus = "loading";
        state.error = null;
      })
      .addCase(updateCourse.fulfilled, (state, action) => {
        state.updateStatus = "succeeded";
        const updatedCourse = action.payload.course || action.payload;

        // Update in courses array
        const courseIndex = state.courses.findIndex(
          (course) =>
            course._id === updatedCourse._id || course.id === updatedCourse.id
        );
        if (courseIndex !== -1) {
          state.courses[courseIndex] = updatedCourse;
        }

        // Update current course if it's the same
        if (
          state.currentCourse &&
          (state.currentCourse._id === updatedCourse._id ||
            state.currentCourse.id === updatedCourse.id)
        ) {
          state.currentCourse = updatedCourse;
        }

        state.error = null;
      })
      .addCase(updateCourse.rejected, (state, action) => {
        state.updateStatus = "failed";
        state.error = action.payload;
      })

      // Delete Course
      .addCase(deleteCourse.pending, (state) => {
        state.deleteStatus = "loading";
        state.error = null;
      })
      .addCase(deleteCourse.fulfilled, (state, action) => {
        state.deleteStatus = "succeeded";
        const deletedId = action.payload.deletedId;

        // Remove from courses array
        state.courses = state.courses.filter(
          (course) => course._id !== deletedId && course.id !== deletedId
        );

        // Remove from published courses if exists
        state.publishedCourses = state.publishedCourses.filter(
          (course) => course._id !== deletedId && course.id !== deletedId
        );

        // Clear current course if it's the deleted one
        if (
          state.currentCourse &&
          (state.currentCourse._id === deletedId ||
            state.currentCourse.id === deletedId)
        ) {
          state.currentCourse = null;
        }

        state.totalCourses = Math.max(0, state.totalCourses - 1);
        state.error = null;
      })
      .addCase(deleteCourse.rejected, (state, action) => {
        state.deleteStatus = "failed";
        state.error = action.payload;
      })
      .addCase(getAllCategories.pending, (state) => {
        state.status = "loading";
        state.error = null;
      })

      .addCase(getAllCategories.fulfilled, (state, action) => {
        state.status = "succeeded";
        state.categories = action.payload.categories || action.payload;
        state.error = null;
      })

      .addCase(getAllCategories.rejected, (state, action) => {
        state.status = "failed";
        state.error = action.payload;
      })
      // Toggle Publish Course
      .addCase(togglePublishCourse.pending, (state) => {
        state.publishStatus = "loading";
        state.error = null;
      })
      .addCase(togglePublishCourse.fulfilled, (state, action) => {
        state.publishStatus = "succeeded";
        const updatedCourse = action.payload.course || action.payload;

        // Update in courses array
        const courseIndex = state.courses.findIndex(
          (course) =>
            course._id === updatedCourse._id || course.id === updatedCourse.id
        );
        if (courseIndex !== -1) {
          state.courses[courseIndex] = updatedCourse;
        }

        // Update current course if it's the same
        if (
          state.currentCourse &&
          (state.currentCourse._id === updatedCourse._id ||
            state.currentCourse.id === updatedCourse.id)
        ) {
          state.currentCourse = updatedCourse;
        }

        // Update published courses array based on new status
        if (updatedCourse.isPublished || updatedCourse.published) {
          // Add to published courses if not already there
          const publishedIndex = state.publishedCourses.findIndex(
            (course) =>
              course._id === updatedCourse._id || course.id === updatedCourse.id
          );
          if (publishedIndex === -1) {
            state.publishedCourses.push(updatedCourse);
          } else {
            state.publishedCourses[publishedIndex] = updatedCourse;
          }
        } else {
          // Remove from published courses
          state.publishedCourses = state.publishedCourses.filter(
            (course) =>
              course._id !== updatedCourse._id && course.id !== updatedCourse.id
          );
        }

        state.error = null;
      })
      .addCase(togglePublishCourse.rejected, (state, action) => {
        state.publishStatus = "failed";
        state.error = action.payload;
      });
  },
});

export const {
  clearError,
  clearCurrentCourse,
  resetCourseState,
  setPagination,
} = courseSlice.actions;

export default courseSlice.reducer;
