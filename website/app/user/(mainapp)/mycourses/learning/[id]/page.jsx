"use client";
import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams } from "next/navigation";
import { getCourseById } from "@/lib/store/features/courseSlice";
import { Button } from "@/components/ui/button";
import { VideoPlayer } from "@/components/videoPlayer";

const LearningPage = () => {
  const { id } = useParams();
  const dispatch = useDispatch();
  const { currentCourse, status, error } = useSelector((state) => state.course);

  const [activeLesson, setActiveLesson] = useState(null);

  useEffect(() => {
    if (id) {
      dispatch(getCourseById(id));
    }
  }, [id, dispatch]);

  useEffect(() => {
    if (currentCourse && currentCourse.sections?.length > 0) {
      // set first lesson as default
      setActiveLesson(currentCourse.sections[0].lessons[0]);
    }
  }, [currentCourse]);

  if (status === "loading") return <div>Loading course...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!currentCourse) return <div>No course found.</div>;

  return (
    <div className="flex h-screen">
      {/* Main Player Area */}
      <div className="flex-1 p-4">
        {activeLesson ? (
          <div>
            <h1 className="text-2xl font-bold mb-2">{currentCourse.title}</h1>
            <h2 className="text-lg font-semibold mb-4">{activeLesson.title}</h2>
            <VideoPlayer
              className="w-full h-[500px] rounded-md bg-black"
              url={activeLesson.videoUrl}
              title={activeLesson.title}
            />
            <p className="mt-3 text-sm text-gray-600">
              {activeLesson.description}
            </p>
          </div>
        ) : (
          <div>Select a lesson to start learning</div>
        )}
      </div>

      {/* Sidebar */}
      <div className="w-96 border-l bg-gray-50 overflow-y-auto p-4">
        <h3 className="text-lg font-bold mb-4">Course Content</h3>
        {currentCourse.sections.map((section, sIndex) => (
          <div key={section._id} className="mb-4">
            <h4 className="font-semibold text-gray-700">
              {sIndex + 1}. {section.title}
            </h4>
            <ul className="ml-2 mt-2 space-y-2">
              {section.lessons.map((lesson, lIndex) => (
                <li key={lesson._id}>
                  <Button
                    variant={
                      activeLesson?._id === lesson._id ? "default" : "outline"
                    }
                    className="w-full justify-start text-left"
                    onClick={() => setActiveLesson(lesson)}
                  >
                    {lIndex + 1}. {lesson.title}{" "}
                    <span className="ml-auto text-xs text-gray-500">
                      {lesson.duration} min
                    </span>
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
};

export default LearningPage;
