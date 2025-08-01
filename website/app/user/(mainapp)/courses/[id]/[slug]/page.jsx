"use client";

import { useEffect, useState, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams } from "next/navigation";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Accordion,
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from "@/components/ui/accordion";
import {
  Star,
  Clock,
  CheckCircle,
  PlayCircle,
  Lock,
  BookOpen,
  Users,
  Award,
  Globe,
  ListChecks,
} from "lucide-react";
import Image from "next/image";
import { getCourseById } from "@/lib/store/features/courseSlice";
import { VideoPlayer } from "@/components/videoPlayer";
import { Spinner } from "@/components/laoder";
import { checkCourseAccess } from "@/lib/store/features/enrollmentSlice";
// import PaymentModal from "@/app/user/components/paymentModal";

const CourseById = () => {
  const { id } = useParams();
  const dispatch = useDispatch();
  const { user, isAuthenticated } = useSelector((state) => state.auth);

  const { currentCourse, status, error } = useSelector((state) => state.course);
  const [previewVideoUrl, setPreviewVideoUrl] = useState("");
  const [isEnrolling, setIsEnrolling] = useState(false);

  // Add ref for video player section
  const videoPlayerRef = useRef(null);

  useEffect(() => {
    dispatch(getCourseById(id));
  }, [dispatch, id]);
  // useEffect(() => {
  //   if (isAuthenticated && currentCourse) {
  //     dispatch(checkCourseAccess(id));
  //   }
  // }, [dispatch, id, isAuthenticated, currentCourse]);

  // Function to handle lesson click
  const handleLessonClick = (lesson) => {
    if (lesson.isFree) {
      setPreviewVideoUrl(lesson.videoUrl);

      // Scroll to video player with smooth animation
      if (videoPlayerRef.current) {
        videoPlayerRef.current.scrollIntoView({
          behavior: "smooth",
          block: "start",
          inline: "nearest",
        });
      }
    }
  };
  const handleEnrollment = async () => {
    if (!isAuthenticated) {
      toast.error("Please login to enroll in the course");
      router.push("/user/login");
      return;
    }

    if (!currentCourse) return;

    setIsEnrolling(true);

    try {
      const enrollmentData = {
        paymentMethod:
          currentCourse.isFree || currentCourse.price === 0 ? "free" : "stripe",
      };

      const result = await dispatch(
        enrollInCourse({
          courseId: id,
          paymentData: enrollmentData,
        })
      ).unwrap();

      if (currentCourse.isFree || currentCourse.price === 0) {
        toast.success("Successfully enrolled in the course!");
        // Refresh course access
        dispatch(checkCourseAccess(id));
      } else {
        // Handle payment flow here
        toast.info("Redirecting to payment...");
        // You can integrate with Stripe, PayPal, etc. here
        handlePayment(result);
      }
    } catch (error) {
      toast.error(error || "Failed to enroll in course");
    } finally {
      setIsEnrolling(false);
    }
  };

  // Handle payment (placeholder for payment integration)
  const handlePayment = (paymentData) => {
    // This is where you'd integrate with your payment provider
    console.log("Payment data:", paymentData);

    // For demo purposes, simulate successful payment
    setTimeout(() => {
      toast.success("Payment successful! You are now enrolled.");
      dispatch(checkCourseAccess(id));
    }, 2000);
  };

  // Get enrollment button text and state
  // const getEnrollmentButtonProps = () => {
  //   if (!isAuthenticated) {
  //     return {
  //       text: "Login to Enroll",
  //       disabled: false,
  //       variant: "default",
  //     };
  //   }

  //   if (accessStatus === "loading") {
  //     return {
  //       text: "Checking Access...",
  //       disabled: true,
  //       variant: "default",
  //     };
  //   }

  //   if (courseAccess?.hasAccess) {
  //     return {
  //       text: "Already Enrolled",
  //       disabled: true,
  //       variant: "secondary",
  //     };
  //   }

  //   if (currentCourse?.isFree || currentCourse?.price === 0) {
  //     return {
  //       text: isEnrolling ? "Enrolling..." : "Enroll for Free",
  //       disabled: isEnrolling,
  //       variant: "default",
  //     };
  //   }

  //   return {
  //     text: isEnrolling ? "Processing..." : "Enroll Now",
  //     disabled: isEnrolling,
  //     variant: "default",
  //   };
  // };
  const handleDemoPayment = async () => {
    setIsProcessing(true);

    // Simulate payment processing
    setTimeout(async () => {
      try {
        await dispatch(
          completeEnrollment({
            paymentId: paymentData.paymentId,
            transactionId: `demo_${Date.now()}`,
            metadata: {
              demo: true,
              amount: course.discountPrice || course.price,
            },
          })
        ).unwrap();

        toast.success("Demo payment successful! You are now enrolled.");
        onSuccess();
        onClose();
      } catch (error) {
        toast.error("Enrollment failed. Please try again.");
      } finally {
        setIsProcessing(false);
      }
    }, 2000);
  };

  if (status === "loading") return <Spinner />;
  if (status === "failed")
    return (
      <div className="text-center py-10 text-red-600 font-semibold">
        Error: {error}
      </div>
    );
  if (!currentCourse)
    return (
      <div className="text-center py-10 font-medium">Course not found</div>
    );

  // const buttonProps = getEnrollmentButtonProps();

  if (status === "loading") return <Spinner />;
  if (status === "failed")
    return (
      <div className="text-center py-10 text-red-600 font-semibold">
        Error: {error}
      </div>
    );
  if (!currentCourse)
    return (
      <div className="text-center py-10 font-medium">Course not found</div>
    );

  const formatDuration = (minutes) => {
    const h = Math.floor(minutes / 60);
    const m = minutes % 60;
    return h ? `${h}h ${m}m` : `${m}m`;
  };

  const totalLessons = currentCourse.sections.reduce(
    (sum, s) => sum + s.lessons.length,
    0
  );
  const totalFreeLessons = currentCourse.sections.reduce(
    (acc, section) => acc + section.lessons.filter((l) => l.isFree).length,
    0
  );

  return (
    <div className="w-full bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Info */}
          <div className="lg:col-span-2 space-y-6">
            <div className="space-y-3">
              <div className="text-sm flex items-center gap-2 flex-wrap">
                <Badge variant="secondary">{currentCourse.level}</Badge>
                <Badge variant="outline" className="flex items-center gap-1">
                  <Globe className="h-3 w-3" /> {currentCourse.language}
                </Badge>
                {currentCourse.isPublished && (
                  <Badge className="flex items-center gap-1">
                    <CheckCircle className="h-3 w-3" /> Published
                  </Badge>
                )}
              </div>
              <h1 className="text-4xl font-bold leading-tight tracking-tight">
                {currentCourse.title}
              </h1>
              <p className="text-muted-foreground text-lg max-w-2xl">
                {currentCourse.description}
              </p>
              <div className="flex items-center flex-wrap gap-5 pt-2 text-sm text-muted-foreground">
                <div className="flex items-center gap-1">
                  <Star className="h-4 w-4 text-yellow-500 fill-yellow-500" />
                  {currentCourse.rating.average.toFixed(1)} (
                  {currentCourse.rating.count} ratings)
                </div>
                <div className="flex items-center gap-1">
                  <Users className="h-4 w-4" />{" "}
                  {currentCourse.enrolledUsers.length} students
                </div>
                <div className="flex items-center gap-1">
                  <BookOpen className="h-4 w-4" />{" "}
                  {currentCourse.sections.length} sections, {totalLessons}{" "}
                  lessons
                </div>
              </div>
            </div>

            {/* Video Preview - Add ref here */}
            <div
              ref={videoPlayerRef}
              className="relative rounded-xl overflow-hidden shadow-lg aspect-video bg-muted"
            >
              {previewVideoUrl ? (
                <VideoPlayer
                  url={previewVideoUrl}
                  title={currentCourse.title}
                />
              ) : (
                <div className="relative rounded-xl overflow-hidden shadow-lg aspect-video bg-muted">
                  <Image
                    unoptimized
                    fill
                    src={currentCourse.thumbnail}
                    alt={currentCourse.title}
                    className="object-cover"
                  />
                  {/* Add overlay text to indicate no video selected */}
                </div>
              )}
            </div>

            {/* What You'll Learn */}
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-xl">
                  <ListChecks className="h-5 w-5" /> What you'll learn
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="grid grid-cols-1 md:grid-cols-2 gap-x-10 gap-y-2 text-sm">
                  {currentCourse.whatYouWillLearn.map((item, idx) => (
                    <li key={idx} className="flex gap-2">
                      <CheckCircle className="text-green-500 h-4 w-4 mt-0.5" />
                      {item}
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            {/* Course Content */}
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle className="text-xl">Course Content</CardTitle>
                <CardDescription>
                  {currentCourse.sections.length} sections • {totalLessons}{" "}
                  lessons • {formatDuration(currentCourse.totalDuration)} total
                  length
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Accordion type="multiple" className="space-y-2">
                  {currentCourse.sections.map((section) => (
                    <AccordionItem key={section._id} value={section._id}>
                      <AccordionTrigger className="hover:no-underline font-semibold">
                        {section.title}{" "}
                        <span className="ml-auto text-xs text-muted-foreground">
                          {section.lessons.length} lessons •{" "}
                          {formatDuration(
                            section.lessons.reduce((a, b) => a + b.duration, 0)
                          )}
                        </span>
                      </AccordionTrigger>
                      <AccordionContent>
                        {section.lessons.map((lesson) => (
                          <div
                            onClick={() => handleLessonClick(lesson)}
                            key={lesson._id}
                            className={`flex items-center justify-between px-2 py-2 rounded transition-colors ${
                              lesson.isFree
                                ? "hover:bg-green-50 cursor-pointer"
                                : "hover:bg-muted/40 cursor-not-allowed"
                            }`}
                          >
                            <div className="flex items-center gap-2">
                              {lesson.isFree ? (
                                <PlayCircle className="text-green-500 h-4 w-4" />
                              ) : (
                                <Lock className="text-muted-foreground h-4 w-4" />
                              )}
                              <span
                                className={`text-sm ${
                                  lesson.isFree
                                    ? "text-green-700 font-medium"
                                    : ""
                                }`}
                              >
                                {lesson.title}
                              </span>
                              {lesson.isFree && (
                                <Badge
                                  variant="outline"
                                  className="text-xs text-green-600 border-green-200"
                                >
                                  Free Preview
                                </Badge>
                              )}
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {formatDuration(lesson.duration)}
                            </span>
                          </div>
                        ))}
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              </CardContent>
            </Card>

            {/* Requirements */}
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle className="text-xl">Requirements</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="list-disc pl-5 space-y-1 text-sm">
                  {currentCourse.requirements.map((req, idx) => (
                    <li key={idx}>{req}</li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Pricing */}
            <Card className="sticky top-4 shadow-xl border border-border">
              <CardHeader>
                <div className="flex items-center gap-3">
                  {currentCourse.discountPrice && (
                    <span className="text-2xl font-bold text-primary">
                      ${currentCourse.discountPrice}
                    </span>
                  )}
                  {currentCourse.price && (
                    <span
                      className={`text-lg ${
                        currentCourse.discountPrice
                          ? "line-through text-muted-foreground"
                          : "font-bold"
                      }`}
                    >
                      ${currentCourse.price}
                    </span>
                  )}
                  {currentCourse.discountPrice && (
                    <Badge variant="destructive" className="ml-auto">
                      {Math.round(
                        ((currentCourse.price - currentCourse.discountPrice) /
                          currentCourse.price) *
                          100
                      )}
                      % OFF
                    </Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <Button
                  onClick={handleDemoPayment}
                  size="lg"
                  className="w-full"
                >
                  Enroll Now
                </Button>
                <div className="space-y-2 text-sm text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <Clock className="h-4 w-4" />{" "}
                    {formatDuration(currentCourse.totalDuration)}
                  </div>
                  <div className="flex items-center gap-2">
                    <PlayCircle className="h-4 w-4" /> {totalFreeLessons} free
                    lessons
                  </div>
                  {currentCourse.certificateEnabled && (
                    <div className="flex items-center gap-2">
                      <Award className="h-4 w-4" /> Certificate of completion
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Category & Tags */}
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle className="text-xl">Categories & Tags</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-1">
                    Category
                  </h4>
                  <Badge variant="outline" className="capitalize">
                    {currentCourse.category.name}
                  </Badge>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-muted-foreground mb-1">
                    Tags
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {currentCourse.tags.map((tag) => (
                      <Badge key={tag} variant="outline" className="capitalize">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
            {/* <PaymentModal
              isOpen={showPaymentModal}
              onClose={() => setShowPaymentModal(false)}
              course={currentCourse}
              paymentData={paymentData}
              onSuccess={handlePaymentSuccess}
            /> */}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CourseById;
