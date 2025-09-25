"use client";
import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { getMyEnrolledCourses } from "@/lib/store/features/courseSlice";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { toast } from "sonner"; // optional toast for feedback
import Link from "next/link";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";

const MyCourses = () => {
  const dispatch = useDispatch();

  const { myEnrolledcourses, status, error } = useSelector(
    (state) => state.course
  );

  useEffect(() => {
    dispatch(getMyEnrolledCourses());
  }, []);

  const handleShare = (course) => {
    const url = `${window.location.origin}/user/courses/${course._id}/${course.slug}`;
    navigator.clipboard.writeText(url).then(() => {
      toast.success("Course link copied to clipboard!");
    });
  };

  if (status === "loading") return <div>Loading courses...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!myEnrolledcourses || myEnrolledcourses.length === 0)
    return <div>No courses enrolled yet.</div>;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 p-4">
      {myEnrolledcourses.map((enrollment) => {
        const { course, progress } = enrollment;
        return (
          <Card key={course._id}>
            <CardHeader>
              <CardTitle>{course.title}</CardTitle>
              <CardDescription>{course.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <img
                src={getMediaUrl(course.thumbnail)}
                alt={course.title}
                className="w-full h-40 object-cover rounded-md mb-2"
              />
              <p>Category: {course.category.name}</p>
              <p>
                Price:{" "}
                {course.isFree
                  ? "Free"
                  : `$${course.discountPrice || course.price}`}
              </p>
              <Progress
                value={progress?.completionPercentage || 0}
                className="mt-2"
              />
              <p className="text-sm mt-1">
                {progress?.completionPercentage || 0}% completed
              </p>
            </CardContent>
            <CardFooter className="flex justify-between">
              <Link href={`/user/mycourses/learning/${course._id}`}>
                <Button>Go to Course</Button>
              </Link>
              <Button variant="outline" onClick={() => handleShare(course)}>
                Share
              </Button>
            </CardFooter>
          </Card>
        );
      })}
    </div>
  );
};

export default MyCourses;
