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
import { CheckCircle, Circle, Download } from "lucide-react";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";

const LearningPage = () => {
  const { id } = useParams();
  const dispatch = useDispatch();

  const { currentCourse, status, error } = useSelector((state) => state.course);
  const { currentEnrollment, courseAccess } = useSelector(
    (state) => state.enrollment
  );

  const [activeLesson, setActiveLesson] = useState(null);
  const [completedLessons, setCompletedLessons] = useState(new Set());
  const [isCourseCompleted, setIsCourseCompleted] = useState(false);
  const [isMarkingCompleted, setIsMarkingCompleted] = useState(false);

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

  // Update completed lessons and check course completion
  useEffect(() => {
    let completedLessonsArray = [];
    let totalLessons = 0;

    // Calculate total lessons in course
    if (currentCourse?.sections) {
      totalLessons = currentCourse.sections.reduce(
        (total, section) => total + (section.lessons?.length || 0),
        0
      );
    }

    // Debug: Log the current enrollment structure
    console.log("currentEnrollment:", currentEnrollment);
    console.log("courseAccess:", courseAccess);

    // Check all possible sources for completed lessons
    if (currentEnrollment?.progress?.completedLessons) {
      // This is the main source - from markLessonCompleted.fulfilled
      completedLessonsArray = currentEnrollment.progress.completedLessons;
    } else if (courseAccess?.enrollment?.progress?.completedLessons) {
      completedLessonsArray = courseAccess.enrollment.progress.completedLessons;
    } else if (currentEnrollment?.enrollment?.progress?.completedLessons) {
      completedLessonsArray =
        currentEnrollment.enrollment.progress.completedLessons;
    }

    console.log("completedLessonsArray:", completedLessonsArray);

    if (completedLessonsArray && completedLessonsArray.length > 0) {
      const completedSet = new Set(
        completedLessonsArray.map((lesson) => lesson.lessonId)
      );
      setCompletedLessons(completedSet);

      // Check if course is completed
      if (totalLessons > 0 && completedSet.size >= totalLessons) {
        setIsCourseCompleted(true);
      } else {
        setIsCourseCompleted(false);
      }
    } else {
      setCompletedLessons(new Set());
      setIsCourseCompleted(false);
    }
  }, [courseAccess, currentEnrollment, currentCourse]);

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

  const handleMarkCompleted = async () => {
    let enrollmentId;

    // Get enrollment ID from either source
    if (courseAccess?.enrollment?._id) {
      enrollmentId = courseAccess.enrollment._id;
    } else if (currentEnrollment?._id) {
      enrollmentId = currentEnrollment._id;
    } else if (currentEnrollment?.enrollment?._id) {
      enrollmentId = currentEnrollment.enrollment._id;
    }

    if (enrollmentId && activeLesson) {
      setIsMarkingCompleted(true);
      try {
        // Optimistically update the UI first
        setCompletedLessons((prev) => new Set(prev).add(activeLesson._id));

        const result = await dispatch(
          markLessonCompleted({
            enrollmentId: enrollmentId,
            lessonData: {
              sectionId: activeLesson.sectionId,
              lessonId: activeLesson._id,
              watchTime: activeLesson.duration * 60,
            },
          })
        ).unwrap();

        console.log("Mark completed result:", result);

        // The Redux store should be updated automatically by the fulfilled case
        // Let's also manually update our local state to be sure
        if (result.progress?.completedLessons) {
          const completedSet = new Set(
            result.progress.completedLessons.map((lesson) => lesson.lessonId)
          );
          setCompletedLessons(completedSet);
        }
      } catch (error) {
        console.error("Failed to mark lesson as completed:", error);
        // Revert optimistic update if there was an error
        setCompletedLessons((prev) => {
          const newSet = new Set(prev);
          newSet.delete(activeLesson._id);
          return newSet;
        });
      } finally {
        setIsMarkingCompleted(false);
      }
    }
  };

  const handleDownloadCertificate = () => {
    // Implement certificate download logic here
    console.log("Downloading certificate...");
    // This would typically call an API endpoint to generate/download the certificate
    alert("Certificate download functionality would be implemented here");
  };

  if (status === "loading") return <div>Loading course...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!currentCourse) return <div>No course found.</div>;

  const hasAccess = courseAccess?.hasAccess;
  const certificateEnabled = currentCourse.certificateEnabled;

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
            <div className="flex justify-between items-start mb-6">
              <div>
                <h1 className="text-2xl font-bold mb-2">
                  {currentCourse.title}
                </h1>
                <h2 className="text-lg font-semibold">
                  {activeLesson.title}
                  {isLessonCompleted(activeLesson._id) && (
                    <CheckCircle
                      className="inline-block ml-2 text-green-500"
                      size={20}
                    />
                  )}
                </h2>
              </div>

              <div className="flex flex-col items-end gap-3">
                {isCourseCompleted && certificateEnabled && (
                  <Button
                    onClick={handleDownloadCertificate}
                    className="flex items-center gap-2"
                  >
                    <Download size={16} />
                    Download Certificate
                  </Button>
                )}

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
            </div>

            {hasAccess ? (
              <>
                <VideoPlayer
                  url={getMediaUrl(activeLesson.videoUrl)}
                  title={activeLesson.title}
                  trackProgress={true}
                  onComplete={handleMarkCompleted}
                />
                {!isLessonCompleted(activeLesson._id) && (
                  <div className="mt-4">
                    <Button
                      onClick={handleMarkCompleted}
                      disabled={isMarkingCompleted}
                    >
                      {isMarkingCompleted ? "Marking..." : "Mark as Completed"}
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

            {/* Progress indicator */}
            <div className="mt-6">
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-medium text-gray-700">
                  Course Progress
                </span>
                <span className="text-sm text-gray-500">
                  {completedLessons.size} /{" "}
                  {currentCourse.sections.reduce(
                    (total, section) => total + (section.lessons?.length || 0),
                    0
                  )}{" "}
                  lessons completed
                </span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2.5">
                <div
                  className="bg-blue-600 h-2.5 rounded-full"
                  style={{
                    width: `${
                      (completedLessons.size /
                        currentCourse.sections.reduce(
                          (total, section) =>
                            total + (section.lessons?.length || 0),
                          0
                        )) *
                      100
                    }%`,
                  }}
                ></div>
              </div>
            </div>
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
