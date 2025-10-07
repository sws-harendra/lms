"use client";

import { useEffect, useState, useRef } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams, useRouter } from "next/navigation";
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
  Calendar,
  Zap,
  Heart,
  Share2,
  Download,
  Shield,
} from "lucide-react";
import Image from "next/image";
import {
  getCourseById,
  getCourseReviews,
} from "@/lib/store/features/courseSlice";
import { VideoPlayer } from "@/components/videoPlayer";
import { Spinner } from "@/components/laoder";
import {
  checkCourseAccess,
  enrollInCourse,
} from "@/lib/store/features/enrollmentSlice";
import { toast } from "sonner";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";
import { enrollmentService } from "@/services/user/enrollment.service";

const CourseById = () => {
  const { id } = useParams();
  const dispatch = useDispatch();
  const { user, isAuthenticated } = useSelector((state) => state.auth);
  const { settings } = useSelector((state) => state.appSettings);
  const router = useRouter();
  const {
    currentCourse,
    status,
    error,
    reviews,
    reviewsStatus,
    reviewsPagination,
  } = useSelector((state) => state.course);
  const { courseAccess } = useSelector((state) => state.enrollment);
  const [previewVideoUrl, setPreviewVideoUrl] = useState("");
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  // Add ref for video player section
  const videoPlayerRef = useRef(null);

  useEffect(() => {
    if (id) {
      dispatch(getCourseById(id));
    }
  }, [dispatch, id]);

  // Fetch reviews when course is available
  useEffect(() => {
    if (currentCourse?._id || id) {
      dispatch(getCourseReviews({ courseId: id, page: 1, limit: 10 }));
    }
  }, [dispatch, id, currentCourse?._id]);

  useEffect(() => {
    if (isAuthenticated && currentCourse) {
      dispatch(checkCourseAccess(id));
    }
  }, [dispatch, id, isAuthenticated, currentCourse]);

  const loadRazorpayScript = () => {
    return new Promise((resolve) => {
      if (document.querySelector("#razorpay-sdk")) {
        resolve(true);
        return;
      }

      const script = document.createElement("script");
      script.id = "razorpay-sdk";
      script.src = "https://checkout.razorpay.com/v1/checkout.js";
      script.onload = () => resolve(true);
      script.onerror = () => resolve(false);
      document.body.appendChild(script);
    });
  };

  const generateOrderId = async () => {
    try {
      const loaded = await loadRazorpayScript();
      if (!loaded) {
        throw new Error("Razorpay SDK failed to load. Check your network.");
      }

      const orderData = {
        amount: currentCourse.discountPrice * 100,
        currency: "INR",
        receiptId: `receipt_${user._id}_${Date.now()}`.slice(0, 40),
      };

      const response = await enrollmentService.createRazorPayOrder(orderData);
      if (!response.success) {
        throw new Error(response.error || "Failed to create order");
      }

      const options = {
        key: response.razorPayKey,
        amount: response.amount,
        currency: response.currency,
        name: "Testing",
        description: "Course Payment",
        order_id: response.orderId,
        handler: async function (res) {
          console.log("Payment success:", res);

          try {
            const enrollmentData = {
              paymentMethod: "razorpay",
              transactionId: res.razorpay_payment_id,
              paymentStatus: "completed",
            };

            await dispatch(
              enrollInCourse({
                courseId: id,
                paymentData: enrollmentData,
              })
            ).unwrap();

            toast.success("Payment successful! You are now enrolled.");
          } catch (err) {
            console.error(err);
            toast.error("Error verifying payment");
          }
        },

        prefill: {
          name: user?.name || "Guest",
          email: user?.email || "guest@example.com",
          contact: user?.phoneNumber || "9999999999",
        },
        theme: { color: "#3399cc" },
      };

      const rzp = new window.Razorpay(options);
      rzp.open();

      return response.orderId;
    } catch (error) {
      console.error("Order creation failed:", error);
      throw error;
    }
  };

  const handleLessonClick = (lesson) => {
    // If enrolled, allow access to all lessons, otherwise only free lessons
    if (lesson.isFree || courseAccess?.hasAccess) {
      setPreviewVideoUrl(lesson.videoUrl);

      if (videoPlayerRef.current) {
        videoPlayerRef.current.scrollIntoView({
          behavior: "smooth",
          block: "start",
          inline: "nearest",
        });
      }
    } else {
      // If not enrolled and lesson is not free, show enrollment prompt
      toast.error("Please enroll to access this lesson");
    }
  };
  const handleShare = (course) => {
    const url = `${window.location.origin}/user/courses/${course._id}/${course.slug}`;
    navigator.clipboard.writeText(url).then(() => {
      toast.success("Course link copied to clipboard!");
    });
  };

  const handleEnrollment = async () => {
    if (!isAuthenticated) {
      toast.error("Please login to enroll in the course");
      router.push("/user/login");
      return;
    }

    if (courseAccess?.hasAccess) {
      router.push(`/user/mycourses/learning/${id}`);
      return;
    }

    if (!currentCourse) return;
    setIsEnrolling(true);

    try {
      const enrollmentData = {
        paymentMethod:
          currentCourse.isFree || currentCourse.price === 0 ? "free" : "stripe",
        transactionId:
          currentCourse.isFree || currentCourse.price === 0
            ? undefined
            : `static_txn_${Date.now()}`,
        paymentStatus:
          currentCourse.isFree || currentCourse.price === 0
            ? "completed"
            : "completed",
      };

      const result = await dispatch(
        enrollInCourse({
          courseId: id,
          paymentData: enrollmentData,
        })
      ).unwrap();

      toast.success("Successfully enrolled in the course!");
      router.push(`/user/mycourses/learning/${id}`);
    } catch (error) {
      toast.error(error.message || "Failed to enroll in course");
    } finally {
      setIsEnrolling(false);
    }
  };

  const buyCourse = async () => {
    console.log("handlePlaceOrder");
    setIsProcessing(true);

    try {
      const orderId = await generateOrderId();

      if (!orderId) {
        throw new Error("Failed to generate order ID");
      }
    } catch (error) {
      console.error("Order placement failed:", error);
      alert("Order placement failed. Please try again.");
    } finally {
      setIsProcessing(false);
    }
  };

  const getEnrollmentButtonProps = () => {
    if (!isAuthenticated) {
      return {
        text: "Login to Enroll",
        disabled: false,
        variant: "default",
        onClick: () => router.push("/user/login"),
      };
    }

    if (courseAccess?.hasAccess) {
      return {
        text: "Go to Learning Dashboard",
        disabled: false,
        variant: "secondary",
        onClick: () => router.push(`/user/mycourses/learning/${id}`),
      };
    }

    if (currentCourse?.isFree || currentCourse?.price === 0) {
      return {
        text: isEnrolling ? "Enrolling..." : "Enroll for Free",
        disabled: isEnrolling,
        variant: "default",
        onClick: handleEnrollment,
      };
    }

    return {
      text: isEnrolling ? "Processing..." : "Enroll Now",
      disabled: isEnrolling,
      variant: "default",
      onClick: buyCourse,
    };
  };

  const renderStars = (rating) => {
    return Array.from({ length: 5 }, (_, i) => (
      <Star
        key={i}
        className={`h-4 w-4 ${
          i < rating ? "text-amber-400 fill-amber-400" : "text-gray-300"
        }`}
      />
    ));
  };

  if (status === "loading") return <Spinner />;
  if (status === "failed")
    return (
      <div className="min-h-screen bg-gradient-to-br from-red-50 to-red-100 flex items-center justify-center">
        <div className="text-center py-10 px-6">
          <div className="text-6xl mb-4">😞</div>
          <h2 className="text-2xl font-bold text-red-600 mb-2">
            Oops! Something went wrong
          </h2>
          <p className="text-red-500">{error}</p>
        </div>
      </div>
    );
  if (!currentCourse)
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 flex items-center justify-center">
        <div className="text-center py-10 px-6">
          <div className="text-6xl mb-4">📚</div>
          <h2 className="text-2xl font-bold text-gray-600 mb-2">
            Course not found
          </h2>
          <p className="text-gray-500">
            The course you're looking for doesn't exist.
          </p>
        </div>
      </div>
    );

  const buttonProps = getEnrollmentButtonProps();
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
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Hero Section */}
      <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-blue-600 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-center">
            <div className="lg:col-span-2 space-y-6">
              <div className="flex items-center gap-3 flex-wrap">
                <Badge className="bg-white/20 text-white border-white/30 hover:bg-white/30">
                  <Globe className="h-3 w-3 mr-1" />
                  {currentCourse.level}
                </Badge>
                <Badge className="bg-white/20 text-white border-white/30 hover:bg-white/30">
                  <BookOpen className="h-3 w-3 mr-1" />
                  {currentCourse.language}
                </Badge>
                {courseAccess?.hasAccess && (
                  <Badge className="bg-emerald-500 text-white">
                    <CheckCircle className="h-3 w-3 mr-1" />
                    Enrolled
                  </Badge>
                )}
              </div>

              <div>
                <h1 className="text-4xl lg:text-5xl font-bold leading-tight mb-4">
                  {currentCourse.title}
                </h1>
                <p className="text-xl text-blue-100 mb-6 leading-relaxed">
                  {currentCourse.description}
                </p>
              </div>

              <div className="flex items-center flex-wrap gap-6 text-blue-100">
                <div className="flex items-center gap-2">
                  <div className="flex">
                    {renderStars(Math.floor(currentCourse.rating.average))}
                  </div>
                  <span className="font-semibold text-white">
                    {currentCourse.rating.average.toFixed(1)}
                  </span>
                  <span>({currentCourse.rating.count} reviews)</span>
                </div>
                <div className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  <span>{currentCourse.enrolledUsers.length} students</span>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  <span>{formatDuration(currentCourse.totalDuration)}</span>
                </div>
              </div>

              <div className="flex gap-3">
                {courseAccess?.hasAccess ? (
                  <Button
                    size="lg"
                    className="bg-blue-100 hover:bg-blue-300 text-blue-800 px-6 py-3 rounded-xl"
                    onClick={() =>
                      router.push(`/user/mycourses/learning/${id}`)
                    }
                  >
                    <PlayCircle className="h-5 w-5 mr-2" />
                    Start Learning
                  </Button>
                ) : (
                  <>
                    <Button
                      onClick={() => handleShare(currentCourse)}
                      variant="secondary"
                      size="sm"
                      className="bg-white/20 text-white border-white/30 hover:bg-white/30"
                    >
                      <Share2 className="h-4 w-4 mr-2" />
                      Share
                    </Button>
                  </>
                )}
              </div>
            </div>

            {/* Course thumbnail in hero */}
            <div className="relative">
              <div className="relative rounded-2xl overflow-hidden shadow-2xl aspect-video bg-black/20 backdrop-blur-sm border border-white/20">
                {/* Show course intro video or first free lesson if available */}
                {currentCourse.introVideo ||
                (currentCourse.sections[0]?.lessons[0]?.isFree &&
                  currentCourse.sections[0]?.lessons[0]?.videoUrl) ? (
                  <VideoPlayer
                    url={getMediaUrl(
                      currentCourse.introVideo ||
                        currentCourse.sections[0].lessons[0].videoUrl
                    )}
                    title={currentCourse.title}
                    className="rounded-2xl"
                  />
                ) : (
                  <>
                    <Image
                      unoptimized
                      fill
                      src={getMediaUrl(currentCourse.thumbnail)}
                      alt={currentCourse.title}
                      className="object-cover"
                    />
                    <div className="absolute inset-0 bg-black/20"></div>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <Button
                        size="lg"
                        className="bg-white/90 text-gray-900 hover:bg-white rounded-full h-16 w-16 p-0"
                        onClick={() => {
                          // Find first free lesson and play it
                          const firstFreeLesson = currentCourse.sections
                            .flatMap((section) => section.lessons)
                            .find((lesson) => lesson.isFree);

                          if (firstFreeLesson) {
                            setPreviewVideoUrl(firstFreeLesson.videoUrl);
                            if (videoPlayerRef.current) {
                              videoPlayerRef.current.scrollIntoView({
                                behavior: "smooth",
                                block: "start",
                              });
                            }
                          } else {
                            toast.info(
                              "No preview available. Please enroll to access course content."
                            );
                          }
                        }}
                      >
                        <PlayCircle className="h-8 w-8" />
                      </Button>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-8">
            {/* Video Preview */}
            <div ref={videoPlayerRef} className="space-y-4">
              {previewVideoUrl && (
                <Card className="overflow-hidden shadow-xl border-0 bg-white/80 backdrop-blur-sm">
                  <CardContent className="p-0">
                    <div className="aspect-video">
                      <VideoPlayer
                        url={getMediaUrl(previewVideoUrl)}
                        title={currentCourse.title}
                      />
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>

            {/* What You'll Learn */}
            <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader className="bg-gradient-to-r from-emerald-50 to-teal-50">
                <CardTitle className="flex items-center gap-3 text-2xl text-emerald-800">
                  <div className="p-2 bg-emerald-100 rounded-lg">
                    <ListChecks className="h-6 w-6 text-emerald-600" />
                  </div>
                  What you'll learn
                </CardTitle>
              </CardHeader>
              <CardContent className="p-8">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {currentCourse.whatYouWillLearn.map((item, idx) => (
                    <div key={idx} className="flex gap-3 items-start">
                      <CheckCircle className="text-emerald-500 h-5 w-5 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-700 leading-relaxed">
                        {item}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Course Content */}
            <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader className="bg-gradient-to-r from-blue-50 to-indigo-50">
                <CardTitle className="text-2xl text-blue-800">
                  Course Content
                </CardTitle>
                <CardDescription className="text-blue-600 text-base">
                  {currentCourse.sections.length} sections • {totalLessons}{" "}
                  lessons •{formatDuration(currentCourse.totalDuration)} total
                  length
                </CardDescription>
              </CardHeader>
              <CardContent className="p-6">
                <Accordion type="multiple" className="space-y-3">
                  {currentCourse.sections.map((section, sectionIdx) => (
                    <AccordionItem
                      key={section._id}
                      value={section._id}
                      className="border border-gray-200 rounded-lg overflow-hidden"
                    >
                      <AccordionTrigger className="hover:no-underline font-semibold px-6 py-4 bg-gray-50/80">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 bg-indigo-100 text-indigo-600 rounded-full flex items-center justify-center text-sm font-bold">
                            {sectionIdx + 1}
                          </div>
                          <span>{section.title}</span>
                          <span className="ml-auto text-sm text-gray-500 font-normal">
                            {section.lessons.length} lessons •
                            {formatDuration(
                              section.lessons.reduce(
                                (a, b) => a + b.duration,
                                0
                              )
                            )}
                          </span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-6 pb-4">
                        <div className="space-y-2">
                          {section.lessons.map((lesson, lessonIdx) => {
                            const isAccessible =
                              lesson.isFree || courseAccess?.hasAccess;
                            const isLocked = !isAccessible;

                            return (
                              <div
                                onClick={() => handleLessonClick(lesson)}
                                key={lesson._id}
                                className={`flex items-center justify-between p-3 rounded-lg transition-all duration-200 ${
                                  isAccessible
                                    ? courseAccess?.hasAccess
                                      ? "hover:bg-blue-50 cursor-pointer border-l-4 border-l-blue-400 bg-blue-50/50"
                                      : "hover:bg-emerald-50 cursor-pointer border-l-4 border-l-emerald-400 bg-emerald-50/50"
                                    : "hover:bg-gray-50 cursor-pointer opacity-75 border-l-4 border-l-gray-300"
                                }`}
                              >
                                <div className="flex items-center gap-3">
                                  <div className="w-6 h-6 bg-gray-200 text-gray-600 rounded-full flex items-center justify-center text-xs font-medium">
                                    {lessonIdx + 1}
                                  </div>
                                  {isAccessible ? (
                                    <PlayCircle
                                      className={`h-5 w-5 ${
                                        courseAccess?.hasAccess
                                          ? "text-blue-500"
                                          : "text-emerald-500"
                                      }`}
                                    />
                                  ) : (
                                    <Lock className="text-gray-400 h-5 w-5" />
                                  )}
                                  <div>
                                    <span
                                      className={`font-medium ${
                                        isAccessible
                                          ? "text-gray-800"
                                          : "text-gray-600"
                                      }`}
                                    >
                                      {lesson.title}
                                    </span>
                                    {lesson.isFree && (
                                      <Badge
                                        variant="outline"
                                        className="ml-2 text-xs text-emerald-600 border-emerald-200 bg-emerald-50"
                                      >
                                        Free Preview
                                      </Badge>
                                    )}
                                    {courseAccess?.hasAccess &&
                                      !lesson.isFree && (
                                        <Badge
                                          variant="outline"
                                          className="ml-2 text-xs text-blue-600 border-blue-200 bg-blue-50"
                                        >
                                          Enrolled
                                        </Badge>
                                      )}
                                    {isLocked && (
                                      <Badge
                                        variant="outline"
                                        className="ml-2 text-xs text-gray-600 border-gray-200 bg-gray-50"
                                      >
                                        Locked
                                      </Badge>
                                    )}
                                  </div>
                                </div>
                                <span className="text-sm text-gray-500 font-medium">
                                  {formatDuration(lesson.duration)}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              </CardContent>
            </Card>

            {/* Student Reviews */}
            <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader className="bg-gradient-to-r from-amber-50 to-orange-50">
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-3 text-2xl text-amber-800">
                    <div className="p-2 bg-amber-100 rounded-lg">
                      <Star className="h-6 w-6 text-amber-600" />
                    </div>
                    Student Reviews
                  </CardTitle>
                  <div className="text-right">
                    <div className="flex items-center gap-2 mb-1">
                      <div className="flex">
                        {renderStars(Math.floor(currentCourse.rating.average))}
                      </div>
                      <span className="text-2xl font-bold text-amber-600">
                        {currentCourse.rating.average.toFixed(1)}
                      </span>
                    </div>
                    <p className="text-sm text-amber-600">
                      Based on {currentCourse.rating.count} reviews
                    </p>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-8">
                <div className="space-y-6">
                  {reviews.map((review) => (
                    <div
                      key={review.id}
                      className="border-b border-gray-100 pb-6 last:border-0"
                    >
                      <div className="flex items-start gap-4">
                        <div className="w-12 h-12 bg-gradient-to-br from-indigo-400 to-purple-500 rounded-full flex items-center justify-center text-white font-semibold text-lg flex-shrink-0">
                          {review.user.name[0]}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center justify-between mb-2">
                            <div>
                              <h4 className="font-semibold text-gray-800">
                                {review.user.name}
                              </h4>
                              <div className="flex items-center gap-2 mt-1">
                                <div className="flex">
                                  {renderStars(review.rating)}
                                </div>
                                <span className="text-sm text-gray-500">
                                  {new Date(review.date).toLocaleDateString()}
                                </span>
                              </div>
                            </div>
                          </div>
                          <p className="text-gray-700 leading-relaxed mb-3">
                            {review.comment}
                          </p>
                        </div>
                      </div>
                    </div>
                  ))}

                  {/* <div className="text-center pt-4">
                    <Button
                      variant="outline"
                      className="border-indigo-200 text-indigo-600 hover:bg-indigo-50"
                    >
                      View All Reviews
                    </Button>
                  </div> */}
                </div>
              </CardContent>
            </Card>

            {/* Requirements */}
            <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader className="bg-gradient-to-r from-purple-50 to-pink-50">
                <CardTitle className="flex items-center gap-3 text-2xl text-purple-800">
                  <div className="p-2 bg-purple-100 rounded-lg">
                    <Shield className="h-6 w-6 text-purple-600" />
                  </div>
                  Requirements
                </CardTitle>
              </CardHeader>
              <CardContent className="p-8">
                <ul className="space-y-3">
                  {currentCourse.requirements.map((req, idx) => (
                    <li key={idx} className="flex gap-3 items-start">
                      <div className="w-2 h-2 bg-purple-400 rounded-full mt-2 flex-shrink-0"></div>
                      <span className="text-gray-700 leading-relaxed">
                        {req}
                      </span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Pricing Card */}
            <Card className="sticky top-6 shadow-2xl border-0 bg-white/90 backdrop-blur-sm">
              <CardHeader className="text-center bg-gradient-to-r from-indigo-500 to-purple-600 text-white rounded-t-lg">
                <div className="space-y-2">
                  {currentCourse.discountPrice && (
                    <div className="flex items-center justify-center gap-3">
                      <span className="text-4xl font-bold">
                        {settings?.currency?.symbol}
                        {currentCourse.discountPrice}
                      </span>
                      {currentCourse.price && (
                        <span className="text-xl line-through text-indigo-200">
                          {settings?.currency?.symbol}
                          {currentCourse.price}
                        </span>
                      )}
                    </div>
                  )}
                  {currentCourse.discountPrice && (
                    <Badge className="bg-red-500 hover:bg-red-600 text-white font-bold">
                      Save{" "}
                      {Math.round(
                        ((currentCourse.price - currentCourse.discountPrice) /
                          currentCourse.price) *
                          100
                      )}
                      %
                    </Badge>
                  )}
                  {!currentCourse.discountPrice && currentCourse.price && (
                    <div className="text-4xl font-bold">
                      ${currentCourse.price}
                    </div>
                  )}
                  {(!currentCourse.price || currentCourse.price === 0) && (
                    <div className="text-4xl font-bold text-emerald-300">
                      FREE
                    </div>
                  )}
                </div>
              </CardHeader>
              <CardContent className="p-6 space-y-6">
                <Button
                  onClick={buttonProps.onClick}
                  disabled={buttonProps.disabled}
                  variant={buttonProps.variant}
                  size="lg"
                  className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-semibold py-3 rounded-xl shadow-lg transition-all duration-200 transform hover:scale-105"
                >
                  {buttonProps.text}
                </Button>

                <div className="space-y-4">
                  <div className="text-center text-sm text-gray-600">
                    30-Day Money-Back Guarantee
                  </div>

                  <div className="space-y-3">
                    <div className="flex items-center gap-3 text-sm">
                      <div className="p-1 bg-indigo-100 rounded">
                        <Clock className="h-4 w-4 text-indigo-600" />
                      </div>
                      <span className="text-gray-700">
                        {formatDuration(currentCourse.totalDuration)} on-demand
                        video
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-sm">
                      <div className="p-1 bg-emerald-100 rounded">
                        <PlayCircle className="h-4 w-4 text-emerald-600" />
                      </div>
                      <span className="text-gray-700">
                        {totalFreeLessons} free preview lessons
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-sm">
                      <div className="p-1 bg-purple-100 rounded">
                        <Download className="h-4 w-4 text-purple-600" />
                      </div>
                      <span className="text-gray-700">
                        Downloadable resources
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-sm">
                      <div className="p-1 bg-amber-100 rounded">
                        <Zap className="h-4 w-4 text-amber-600" />
                      </div>
                      <span className="text-gray-700">
                        Full lifetime access
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-sm">
                      <div className="p-1 bg-blue-100 rounded">
                        <Globe className="h-4 w-4 text-blue-600" />
                      </div>
                      <span className="text-gray-700">
                        Access on mobile and TV
                      </span>
                    </div>
                    {currentCourse.certificateEnabled && (
                      <div className="flex items-center gap-3 text-sm">
                        <div className="p-1 bg-orange-100 rounded">
                          <Award className="h-4 w-4 text-orange-600" />
                        </div>
                        <span className="text-gray-700">
                          Certificate of completion
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Course Stats */}
            <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader className="bg-gradient-to-r from-teal-50 to-cyan-50">
                <CardTitle className="text-xl text-teal-800">
                  Course Stats
                </CardTitle>
              </CardHeader>
              <CardContent className="p-6">
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Students Enrolled</span>
                    <span className="font-semibold text-teal-600">
                      {currentCourse.enrolledUsers.length.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Rating</span>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-amber-600">
                        {currentCourse.rating.average.toFixed(1)}
                      </span>
                      <div className="flex">
                        {renderStars(Math.floor(currentCourse.rating.average))}
                      </div>
                    </div>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Last Updated</span>
                    <span className="font-semibold text-gray-700">
                      {new Date(
                        currentCourse.updatedAt || currentCourse.createdAt
                      ).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-600">Language</span>
                    <span className="font-semibold text-gray-700">
                      {currentCourse.language}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Category & Tags */}
            <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-sm">
              <CardHeader className="bg-gradient-to-r from-rose-50 to-pink-50">
                <CardTitle className="text-xl text-rose-800">
                  Categories & Tags
                </CardTitle>
              </CardHeader>
              <CardContent className="p-6 space-y-4">
                <div>
                  <h4 className="text-sm font-medium text-gray-600 mb-2">
                    Category
                  </h4>
                  <Badge className="bg-rose-100 text-rose-700 hover:bg-rose-200 px-3 py-1">
                    {currentCourse.category.name}
                  </Badge>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-600 mb-2">
                    Tags
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {currentCourse.tags.map((tag, index) => (
                      <Badge
                        key={tag}
                        variant="outline"
                        className={`capitalize px-3 py-1 ${
                          index % 3 === 0
                            ? "border-blue-200 text-blue-700 bg-blue-50 hover:bg-blue-100"
                            : index % 3 === 1
                            ? "border-purple-200 text-purple-700 bg-purple-50 hover:bg-purple-100"
                            : "border-green-200 text-green-700 bg-green-50 hover:bg-green-100"
                        }`}
                      >
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Instructor Info (if available) */}
            {currentCourse.instructor && (
              <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-sm">
                <CardHeader className="bg-gradient-to-r from-indigo-50 to-blue-50">
                  <CardTitle className="text-xl text-indigo-800">
                    Instructor
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-6">
                  <div className="flex items-center gap-4">
                    <div className="w-16 h-16 bg-gradient-to-br from-indigo-400 to-purple-500 rounded-full flex items-center justify-center text-white font-bold text-xl">
                      {currentCourse.instructor.name
                        ? currentCourse.instructor.name[0]
                        : "I"}
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-800">
                        {currentCourse.instructor.name || "Course Instructor"}
                      </h3>
                      <p className="text-sm text-gray-600">
                        {currentCourse.instructor.title || "Expert Instructor"}
                      </p>
                    </div>
                  </div>
                  {currentCourse.instructor.bio && (
                    <p className="mt-4 text-sm text-gray-600 leading-relaxed">
                      {currentCourse.instructor.bio}
                    </p>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Similar Courses Suggestion */}
            <Card className="shadow-xl border-0 bg-gradient-to-br from-gray-50 to-gray-100">
              <CardHeader>
                <CardTitle className="text-xl text-gray-800">
                  Explore More
                </CardTitle>
              </CardHeader>
              <CardContent className="p-6">
                <div className="space-y-3">
                  <Button
                    variant="outline"
                    className="w-full justify-start"
                    onClick={() => router.push("/courses")}
                  >
                    <BookOpen className="h-4 w-4 mr-2" />
                    Browse All Courses
                  </Button>
                  <Button
                    variant="outline"
                    className="w-full justify-start"
                    onClick={() =>
                      router.push(
                        `/courses/category/${currentCourse.category.name}`
                      )
                    }
                  >
                    <Globe className="h-4 w-4 mr-2" />
                    More {currentCourse.category.name} Courses
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CourseById;
