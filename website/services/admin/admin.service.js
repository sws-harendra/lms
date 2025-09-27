import axiosInstance from "@/app/utils/axiosinterceptor";

export const adminServices = {
  // Get all courses
  //   instructorProfile: async (params) => {
  //     const response = await axiosInstance.get(
  //       `/admin/get-instructor-profile/${params}`
  //     );
  //     return response.data;
  //   },

  getDashborddata: async () => {
    const response = await axiosInstance.get(`/admin/dashboard`);
    return response.data;
  },
  getAllUsers: async (params = {}) => {
    const response = await axiosInstance.get(`/admin/users`, { params });
    return response.data;
  },
  getUserById: async (id) => {
    const response = await axiosInstance.get(`/admin/users/${id}`);
    return response.data;
  },
  createUser: async (data) => {
    const response = await axiosInstance.post(`/admin/users`, data);
    return response.data;
  },
  updateUser: async (id, data) => {
    const response = await axiosInstance.put(`/admin/users/${id}`, data);
    return response.data;
  },
  deleteUser: async (id) => {
    const response = await axiosInstance.delete(`/admin/users/${id}`);
    return response.data;
  },
};
