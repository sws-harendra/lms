import axiosInstance from "@/app/utils/axiosinterceptor";

export const courseService = {
  // Get all courses
  getAllCourses: async () => {
    const response = await axiosInstance.get("/courses");
    return response.data;
  },

  // Create course (requires authentication and permission)
  createCourse: async (courseData) => {
    const response = await axiosInstance.post("/courses", courseData);
    return response.data;
  },

  // Get published courses
  getPublishedCourses: async () => {
    const response = await axiosInstance.get("/courses/published");
    return response.data;
  },

  // Get course by slug
  getCourseBySlug: async (slug) => {
    const response = await axiosInstance.get(`/courses/slug/${slug}`);
    return response.data;
  },

  // Get course by ID
  getCourseById: async (id) => {
    const response = await axiosInstance.get(`/courses/${id}`);
    return response.data;
  },

  // Update course
  updateCourse: async (id, courseData) => {
    const response = await axiosInstance.put(`/courses/${id}`, courseData);
    return response.data;
  },

  // Delete course
  deleteCourse: async (id) => {
    const response = await axiosInstance.delete(`/courses/${id}`);
    return response.data;
  },

  // Toggle publish status
  togglePublishCourse: async (id) => {
    const response = await axiosInstance.patch(`/courses/toggle-publish/${id}`);
    return response.data;
  },
};
