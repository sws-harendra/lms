"use client";

import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams } from "next/navigation";
import { getCourseById } from "@/lib/store/features/courseSlice";
import {
  checkCourseAccess,
  getEnrollmentDetails,
  markLessonCompleted,
} from "@/lib/store/features/enrollmentSlice";
import { Button } from "@/components/ui/button";
import { VideoPlayer } from "@/components/videoPlayer";
import { CheckCircle, Circle } from "lucide-react";

const LearningPage = () => {
  const { id } = useParams();
  const dispatch = useDispatch();

  const { currentCourse, status, error } = useSelector((state) => state.course);
  const { currentEnrollment, courseAccess } = useSelector(
    (state) => state.enrollment
  );

  const [activeLesson, setActiveLesson] = useState(null);
  const [completedLessons, setCompletedLessons] = useState(new Set());

  useEffect(() => {
    if (id) {
      dispatch(getCourseById(id));
      dispatch(checkCourseAccess(id));
    }
  }, [id, dispatch]);

  useEffect(() => {
    if (courseAccess?.enrollment?._id) {
      dispatch(getEnrollmentDetails(courseAccess.enrollment._id));
    }
  }, [courseAccess, dispatch]);

  // Update completed lessons when enrollment data changes
  useEffect(() => {
    let completedLessonsArray = [];

    // Check both possible sources for completed lessons
    if (courseAccess?.enrollment?.progress?.completedLessons) {
      completedLessonsArray = courseAccess.enrollment.progress.completedLessons;
    } else if (currentEnrollment?.enrollment?.progress?.completedLessons) {
      completedLessonsArray =
        currentEnrollment.enrollment.progress.completedLessons;
    }

    if (completedLessonsArray.length > 0) {
      const completedSet = new Set(
        completedLessonsArray.map((lesson) => lesson.lessonId)
      );
      setCompletedLessons(completedSet);
    }
  }, [courseAccess, currentEnrollment]);

  // Set the first lesson as active when course loads
  useEffect(() => {
    if (currentCourse?.sections?.length > 0) {
      const firstSection = currentCourse.sections[0];
      if (firstSection.lessons?.length > 0) {
        const firstLesson = {
          ...firstSection.lessons[0],
          sectionId: firstSection._id,
        };
        setActiveLesson(firstLesson);
      }
    }
  }, [currentCourse]);

  const handleMarkCompleted = () => {
    let enrollmentId;

    // Get enrollment ID from either source
    if (courseAccess?.enrollment?._id) {
      enrollmentId = courseAccess.enrollment._id;
    } else if (currentEnrollment?.enrollment?._id) {
      enrollmentId = currentEnrollment.enrollment._id;
    }

    if (enrollmentId && activeLesson) {
      dispatch(
        markLessonCompleted({
          enrollmentId: enrollmentId,
          lessonData: {
            sectionId: activeLesson.sectionId,
            lessonId: activeLesson._id,
            watchTime: activeLesson.duration * 60,
          },
        })
      );

      // Optimistically update the UI
      setCompletedLessons((prev) => new Set(prev).add(activeLesson._id));
    }
  };

  if (status === "loading") return <div>Loading course...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!currentCourse) return <div>No course found.</div>;

  const hasAccess = courseAccess?.hasAccess;

  // Helper function to handle lesson selection
  const handleLessonSelect = (section, lesson) => {
    setActiveLesson({
      ...lesson,
      sectionId: section._id,
    });
  };

  // Check if a lesson is completed
  const isLessonCompleted = (lessonId) => completedLessons.has(lessonId);

  return (
    <div className="flex h-screen">
      {/* Main Video */}
      <div className="flex-1 p-4">
        {activeLesson ? (
          <div>
            <div className="flex justify-between">
              <div>
                <h1 className="text-2xl font-bold mb-2">
                  {currentCourse.title}
                </h1>
                <h2 className="text-lg font-semibold mb-4">
                  {activeLesson.title}
                  {isLessonCompleted(activeLesson._id) && (
                    <CheckCircle
                      className="inline-block ml-2 text-green-500"
                      size={20}
                    />
                  )}
                </h2>
              </div>
              <div>
                <h3 className="text-base font-semibold mb-2 text-gray-800">
                  Instructor
                </h3>
                <div className="rounded-xl bg-white px-4 shadow-sm">
                  <div className="flex items-center gap-3">
                    <div className="w-12 h-12 flex items-center justify-center rounded-full bg-gray-200 text-gray-600 font-bold">
                      {currentCourse.instructor?.name?.charAt(0)}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {currentCourse.instructor?.name}
                      </p>
                      <p className="text-xs text-gray-500">
                        {currentCourse.instructor?.email}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {hasAccess ? (
              <>
                <VideoPlayer
                  url={activeLesson.videoUrl}
                  title={activeLesson.title}
                  trackProgress={true}
                  onComplete={handleMarkCompleted}
                />
                {!isLessonCompleted(activeLesson._id) && (
                  <div className="mt-4">
                    <Button onClick={handleMarkCompleted}>
                      Mark as Completed
                    </Button>
                  </div>
                )}
              </>
            ) : (
              <div className="w-full h-[500px] flex items-center justify-center bg-gray-200 rounded-md">
                <p className="text-gray-700">
                  This is a preview. Enroll to unlock the full video.
                </p>
              </div>
            )}

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
              {section.lessons.map((lesson, lIndex) => {
                const isCompleted = isLessonCompleted(lesson._id);
                return (
                  <li key={lesson._id}>
                    <Button
                      variant={
                        activeLesson?._id === lesson._id ? "default" : "outline"
                      }
                      className="w-full justify-start text-left relative"
                      onClick={() => handleLessonSelect(section, lesson)}
                    >
                      <div className="absolute left-2">
                        {isCompleted ? (
                          <CheckCircle className="text-green-500" size={16} />
                        ) : (
                          <Circle className="text-gray-400" size={16} />
                        )}
                      </div>
                      <span className="ml-6">
                        {lIndex + 1}. {lesson.title}
                      </span>
                      <span className="ml-auto text-xs text-gray-500">
                        {lesson.duration} min
                      </span>
                    </Button>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
};

export default LearningPage;
