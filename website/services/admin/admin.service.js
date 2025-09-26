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
};
