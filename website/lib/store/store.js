// /lib/store/store.js
import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./features/authSlice";
import courseReducer from "./features/courseSlice";

// import userReducer from "./features/user/userSlice";
// import instructorReducer from "./features/instructor/instructorSlice";
// import adminReducer from "./features/admin/adminSlice";
// import commonReducer from "./features/common/commonSlice";

export const store = configureStore({
  reducer: {
    auth: authReducer,
    course: courseReducer,
    // instructor: instructorReducer,
    // admin: adminReducer,
    // common: commonReducer,
  },
});
