"use client";

import React, { useEffect, useState } from "react";
import Image from "next/image";
import { useParams } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { instructorServices } from "@/services/instructor.service";
import CourseCard from "@/app/user/components/courseCard";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";

const InstructorProfilePage = () => {
  const params = useParams();
  const instructorId = params.id;

  const [instructor, setInstructor] = useState(null);
  const [courses, setCourses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchInstructor = async () => {
      try {
        setLoading(true);
        const data = await instructorServices.instructorProfile(instructorId);
        setInstructor(data?.instructor || null); // nested object
        setCourses(data?.courses || []); // nested array
      } catch (err) {
        setError("Failed to fetch instructor profile");
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchInstructor();
  }, [instructorId]);

  if (loading) return <p className="text-center py-10">Loading...</p>;
  if (error) return <p className="text-center py-10 text-red-500">{error}</p>;
  if (!instructor)
    return <p className="text-center py-10">Instructor not found</p>;

  return (
    <div className="container mx-auto py-10 space-y-6">
      {/* Profile Header */}
      <Card className="p-6 flex gap-6 items-center flex-col md:flex-row">
        {instructor.profileImage ? (
          <img
            src={getMediaUrl(instructor.profileImage)}
            alt={instructor.name}
            width={120}
            height={120}
            className="rounded-full object-cover"
          />
        ) : (
          <div className="w-28 h-28 rounded-full bg-gray-300 flex items-center justify-center text-3xl font-bold">
            {instructor.name?.charAt(0)}
          </div>
        )}

        <div>
          <h1 className="text-3xl font-bold">{instructor.name}</h1>
          {instructor.designation && (
            <p className="text-sm text-gray-600">{instructor.designation}</p>
          )}
          {instructor.experience && (
            <p className="text-sm text-gray-600">
              {instructor.experience} years experience
            </p>
          )}
          {instructor.shortBio && (
            <p className="mt-2 text-gray-700">{instructor.shortBio}</p>
          )}
        </div>
      </Card>

      {/* Skills */}
      {instructor.skills?.length > 0 && (
        <Card className="p-6">
          <h2 className="text-lg font-semibold mb-3">Skills</h2>
          <div className="flex flex-wrap gap-2">
            {instructor.skills.map((skill) => (
              <Badge key={skill._id} variant="secondary">
                {skill.name} ({skill.expertise}%)
              </Badge>
            ))}
          </div>
        </Card>
      )}

      <Separator />

      {/* Courses */}
      <Card className="p-6">
        <h2 className="text-lg font-semibold mb-3">
          Courses by {instructor.name}
        </h2>
        {courses.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {courses.map((course) => (
              <CourseCard key={course._id} course={course} />
            ))}
          </div>
        ) : (
          <p className="text-gray-600">No courses published yet.</p>
        )}
      </Card>
    </div>
  );
};

export default InstructorProfilePage;
