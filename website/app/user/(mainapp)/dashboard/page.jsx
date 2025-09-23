"use client";
import UserNavbar from "@/components/UsersNavbar";
import Image from "next/image";
import { useSelector } from "react-redux";
import Courses from "../courses/page";

export default function Home() {
  const {
    status,

    user,
  } = useSelector((state) => state.auth);
  return (
    <div className="h-full bg-gray-50">
      <Courses />

      {/* <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Welcome back{user?.name ? `, ${user.name}` : ""}!
          </h1>
          <p className="text-gray-600">
            Continue your learning journey with our available courses
          </p>
        </div>{" "}
      </div> */}
    </div>
  );
}
