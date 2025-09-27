import axiosInstance from "@/app/utils/axiosinterceptor";

export const settingsAdminService = {
  get: async () => {
    const res = await axiosInstance.get(`/settings`);
    return res.data; // { settings }
  },
  update: async (payload) => {
    const res = await axiosInstance.put(`/settings`, payload);
    return res.data; // { message, settings }
  },
};
