// hooks/useAuth.js
import { getUserDetails } from "@/lib/store/features/authSlice";
import { useEffect } from "react";
import { useSelector, useDispatch } from "react-redux";

export const useAuth = () => {
  const dispatch = useDispatch();
  const { user, status } = useSelector((state) => state.auth);

  useEffect(() => {
    if (status === "idle") {
      dispatch(getUserDetails()); // Fetch user if not already loading
    }
  }, [dispatch, status]);

  return { user, isLoading: status === "loading" };
};
