import axiosInstance from "@/app/utils/axiosinterceptor";

export const courseService = {
  // Get all courses
  getAllCourses: async (params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await axiosInstance.get(
      `/course${queryString ? `?${queryString}` : ""}`
    );
    return response.data;
  },

  // Get published courses only
  getPublishedCourses: async (params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    const response = await axiosInstance.get(
      `/courses/published${queryString ? `?${queryString}` : ""}`
    );
    return response.data;
  },

  // Create course (requires authentication and permission)
  createCourse: async (courseData) => {
    const response = await axiosInstance.post("/course", courseData);
    return response.data;
  },

  // Get published courses
  getPublishedCourses: async () => {
    const response = await axiosInstance.get("/course/published");
    return response.data;
  },

  // Get course by slug
  getCourseBySlug: async (slug) => {
    const response = await axiosInstance.get(`/course/slug/${slug}`);
    return response.data;
  },

  // Get course by ID
  getCourseById: async (id) => {
    const response = await axiosInstance.get(`/course/${id}`);
    return response.data;
  },

  // Update course
  updateCourse: async (id, courseData) => {
    const response = await axiosInstance.put(`/course/${id}`, courseData);
    return response.data;
  },

  // Delete course
  deleteCourse: async (id) => {
    const response = await axiosInstance.delete(`/course/${id}`);
    return response.data;
  },

  // Toggle publish status
  togglePublishCourse: async (id) => {
    const response = await axiosInstance.patch(`/course/toggle-publish/${id}`);
    return response.data;
  },
};
