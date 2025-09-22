"use client";
import React from "react";
import Link from "next/link";
import Image from "next/image";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";

const CourseCard = ({ course }) => {
  const {
    _id,
    title,
    description,
    thumbnail,
    price,
    originalPrice,
    instructor,
    category,
    rating,
    studentsEnrolled,
    duration,
    level,
    slug,
    isPublished,
  } = course;

  // Calculate discount percentage
  const discountPercentage =
    originalPrice && price < originalPrice
      ? Math.round(((originalPrice - price) / originalPrice) * 100)
      : 0;

  // Format price
  const formatPrice = (amount) => {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
    }).format(amount);
  };

  // Default thumbnail if none provided

  return (
    <div className="bg-white rounded-lg shadow-md hover:shadow-lg transition-shadow duration-300 overflow-hidden">
      <Link href={`/user/courses/${_id}/${slug}`}>
        <div className="relative">
          {/* Course Thumbnail */}
          <div className="relative h-48 w-full">
            <Image
              src={getMediaUrl(thumbnail)}
              alt={title}
              unoptimized
              fill
              className="object-cover"
              onError={(e) => {
                e.target.src = defaultThumbnail;
              }}
            />
            {/* Discount Badge */}
            {discountPercentage > 0 && (
              <div className="absolute top-2 left-2 bg-red-500 text-white px-2 py-1 rounded text-xs font-bold">
                {discountPercentage}% OFF
              </div>
            )}
            {/* Level Badge */}
            {level && (
              <div className="absolute top-2 right-2 bg-blue-500 text-white px-2 py-1 rounded text-xs font-medium capitalize">
                {level}
              </div>
            )}
          </div>

          {/* Course Content */}
          <div className="p-4">
            {/* Category */}
            {category && (
              <div className="flex items-center mb-2">
                {category.icon && (
                  <span className="mr-1 text-sm">{category.icon}</span>
                )}
                <span className="text-xs text-blue-600 font-medium uppercase tracking-wide">
                  {category.name}
                </span>
              </div>
            )}

            {/* Title */}
            <h3 className="text-lg font-semibold text-gray-900 mb-2 line-clamp-2 hover:text-blue-600 transition-colors">
              {title}
            </h3>

            {/* Description */}
            <p className="text-gray-600 text-sm mb-3 line-clamp-2">
              {description}
            </p>

            {/* Instructor */}
            {instructor && (
              <div className="flex items-center mb-3">
                <div className="w-6 h-6 bg-gray-300 rounded-full flex items-center justify-center mr-2">
                  <span className="text-xs font-medium text-gray-600">
                    {instructor.name?.charAt(0).toUpperCase()}
                  </span>
                </div>
                <span className="text-sm text-gray-700">{instructor.name}</span>
              </div>
            )}

            {/* Course Stats */}
            <div className="flex items-center justify-between mb-3 text-sm text-gray-600">
              <div className="flex items-center space-x-4">
                {/* Rating */}
                {rating && (
                  <div className="flex items-center">
                    <svg
                      className="w-4 h-4 text-yellow-400 mr-1"
                      fill="currentColor"
                      viewBox="0 0 20 20"
                    >
                      <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                    </svg>
                    <span>{rating?.average.toFixed(1)}</span>
                  </div>
                )}

                {/* Students Enrolled */}
                {studentsEnrolled !== undefined && (
                  <div className="flex items-center">
                    <svg
                      className="w-4 h-4 mr-1"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"
                      />
                    </svg>
                    <span>{studentsEnrolled}</span>
                  </div>
                )}

                {/* Duration */}
                {duration && (
                  <div className="flex items-center">
                    <svg
                      className="w-4 h-4 mr-1"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <span>{duration}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Price */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                {price !== undefined && (
                  <>
                    <span className="text-lg font-bold text-gray-900">
                      {price === 0 ? "Free" : formatPrice(price)}
                    </span>
                    {originalPrice && originalPrice > price && (
                      <span className="text-sm text-gray-500 line-through">
                        {formatPrice(originalPrice)}
                      </span>
                    )}
                  </>
                )}
              </div>

              {/* Enroll Button */}
              <button className="bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 transition-colors">
                {price === 0 ? "Enroll Free" : "Enroll Now"}
              </button>
            </div>
          </div>
        </div>
      </Link>
    </div>
  );
};

export default CourseCard;
