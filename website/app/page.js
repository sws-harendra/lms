"use client";
import {
  BookOpen,
  GraduationCap,
  Users,
  Award,
  Clock,
  BarChart2,
  MonitorPlay,
  Globe,
  MessageSquare,
  ShieldCheck,
  LayoutDashboard,
  Rocket,
  ChevronRight,
  Star,
  Check,
} from "lucide-react";
import { brandName } from "./contants";
import Link from "next/link";
import { useSelector } from "react-redux";

const Home = () => {
  const { settings } = useSelector((state) => state.appSettings);

  return (
    <div className="font-sans text-gray-800">
      {/* Navigation */}
      <nav className="fixed w-full bg-white shadow-sm z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-20 items-center">
            <div className="flex items-center">
              <GraduationCap className="h-8 w-8 text-indigo-600" />
              <span className="ml-2 text-2xl font-bold text-indigo-600">
                {settings?.platformName}.
              </span>
            </div>

            <div className="hidden md:flex items-center space-x-8">
              <a
                href="#"
                className="text-gray-700 hover:text-indigo-600 font-medium"
              >
                Home
              </a>
              <a
                href="#"
                className="text-gray-700 hover:text-indigo-600 font-medium"
              >
                Courses
              </a>
              <a
                href="#"
                className="text-gray-700 hover:text-indigo-600 font-medium"
              >
                Features
              </a>
              <a
                href="#"
                className="text-gray-700 hover:text-indigo-600 font-medium"
              >
                Pricing
              </a>
              <a
                href="#"
                className="text-gray-700 hover:text-indigo-600 font-medium"
              >
                About
              </a>
              <Link href="/user/login">
                <button className="bg-indigo-600 text-white px-6 py-2 rounded-full font-medium hover:bg-indigo-700 transition-all">
                  Sign Up
                </button>
              </Link>{" "}
            </div>

            <button className="md:hidden text-gray-700">
              <svg
                className="h-6 w-6"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 6h16M4 12h16M4 18h16"
                />
              </svg>
            </button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 bg-gradient-to-r from-indigo-50 to-purple-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="md:flex items-center justify-between">
            <div className="md:w-1/2 mb-12 md:mb-0">
              <h1 className="text-5xl font-bold leading-tight mb-6 text-gray-900">
                Learn New Skills Online With{" "}
                <span className="text-indigo-600">EduMaster</span>
              </h1>
              <p className="text-xl text-gray-600 mb-8">
                Access 5,000+ courses from top instructors around the globe.
                Grow your skills today.
              </p>
              <div className="flex flex-wrap gap-4">
                <button className="bg-indigo-600 text-white px-8 py-3 rounded-full font-medium hover:bg-indigo-700 transition-all flex items-center">
                  Get Started <ChevronRight className="ml-2 h-5 w-5" />
                </button>
                <button className="border-2 border-indigo-600 text-indigo-600 px-8 py-3 rounded-full font-medium hover:bg-indigo-50 transition-all flex items-center">
                  Browse Courses
                </button>
              </div>
            </div>
            <div className="md:w-1/2">
              <img
                src="https://images.unsplash.com/photo-1522202176988-66273c2fd55f?ixlib=rb-1.2.1&auto=format&fit=crop&w=800&q=80"
                alt="Students learning"
                className="rounded-xl shadow-xl w-full"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
            <div className="p-6">
              <Users className="h-12 w-12 text-indigo-600 mx-auto mb-4" />
              <h3 className="text-4xl font-bold mb-2">50,000+</h3>
              <p className="text-gray-600">Active Students</p>
            </div>
            <div className="p-6">
              <BookOpen className="h-12 w-12 text-indigo-600 mx-auto mb-4" />
              <h3 className="text-4xl font-bold mb-2">5,000+</h3>
              <p className="text-gray-600">Courses</p>
            </div>
            <div className="p-6">
              <Award className="h-12 w-12 text-indigo-600 mx-auto mb-4" />
              <h3 className="text-4xl font-bold mb-2">300+</h3>
              <p className="text-gray-600">Expert Instructors</p>
            </div>
            <div className="p-6">
              <Clock className="h-12 w-12 text-indigo-600 mx-auto mb-4" />
              <h3 className="text-4xl font-bold mb-2">24/7</h3>
              <p className="text-gray-600">Learning Access</p>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">Why Choose {brandName}</h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              We provide the best learning experience with cutting-edge
              technology and expert instructors.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-white p-8 rounded-xl shadow-sm hover:shadow-md transition-shadow">
              <div className="bg-indigo-100 w-16 h-16 rounded-full flex items-center justify-center mb-6">
                <MonitorPlay className="h-8 w-8 text-indigo-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Interactive Lessons</h3>
              <p className="text-gray-600">
                Engaging video lessons with quizzes and hands-on exercises to
                reinforce learning.
              </p>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-sm hover:shadow-md transition-shadow">
              <div className="bg-indigo-100 w-16 h-16 rounded-full flex items-center justify-center mb-6">
                <Globe className="h-8 w-8 text-indigo-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Learn Anywhere</h3>
              <p className="text-gray-600">
                Access courses on any device, anytime with our mobile-friendly
                platform.
              </p>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-sm hover:shadow-md transition-shadow">
              <div className="bg-indigo-100 w-16 h-16 rounded-full flex items-center justify-center mb-6">
                <MessageSquare className="h-8 w-8 text-indigo-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Community Support</h3>
              <p className="text-gray-600">
                Join discussion forums and get help from instructors and peers.
              </p>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-sm hover:shadow-md transition-shadow">
              <div className="bg-indigo-100 w-16 h-16 rounded-full flex items-center justify-center mb-6">
                <ShieldCheck className="h-8 w-8 text-indigo-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Certification</h3>
              <p className="text-gray-600">
                Earn recognized certificates to showcase your new skills.
              </p>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-sm hover:shadow-md transition-shadow">
              <div className="bg-indigo-100 w-16 h-16 rounded-full flex items-center justify-center mb-6">
                <LayoutDashboard className="h-8 w-8 text-indigo-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Progress Tracking</h3>
              <p className="text-gray-600">
                Monitor your learning journey with detailed progress reports.
              </p>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-sm hover:shadow-md transition-shadow">
              <div className="bg-indigo-100 w-16 h-16 rounded-full flex items-center justify-center mb-6">
                <Rocket className="h-8 w-8 text-indigo-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Career Advancement</h3>
              <p className="text-gray-600">
                Gain skills that employers want with career-focused courses.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Popular Courses */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">Popular Courses</h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Start learning with our most popular courses
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {[1, 2, 3].map((item) => (
              <div
                key={item}
                className="bg-white rounded-xl overflow-hidden shadow-md hover:shadow-lg transition-shadow border border-gray-100"
              >
                <div className="h-48 bg-indigo-100 overflow-hidden">
                  <img
                    src={`https://source.unsplash.com/random/600x400?education=${item}`}
                    alt="Course"
                    className="w-full h-full object-cover"
                  />
                </div>
                <div className="p-6">
                  <div className="flex justify-between items-start mb-3">
                    <span className="bg-indigo-100 text-indigo-800 text-xs font-medium px-2.5 py-0.5 rounded">
                      {item === 1
                        ? "Design"
                        : item === 2
                        ? "Development"
                        : "Business"}
                    </span>
                    <div className="flex items-center text-yellow-500">
                      <Star className="h-4 w-4 fill-current" />
                      <span className="ml-1 text-gray-700">4.9</span>
                    </div>
                  </div>
                  <h3 className="text-xl font-bold mb-3">
                    {item === 1
                      ? "UI/UX Design Masterclass"
                      : item === 2
                      ? "Full Stack Web Development"
                      : "Digital Marketing Fundamentals"}
                  </h3>
                  <div className="flex justify-between text-sm text-gray-600 mb-4">
                    <span className="flex items-center">
                      <BookOpen className="h-4 w-4 mr-1" />{" "}
                      {item === 1 ? "12" : item === 2 ? "24" : "8"} Lessons
                    </span>
                    <span className="flex items-center">
                      <Clock className="h-4 w-4 mr-1" />{" "}
                      {item === 1
                        ? "8h 30m"
                        : item === 2
                        ? "32h 15m"
                        : "6h 20m"}
                    </span>
                  </div>
                  <div className="flex justify-between items-center pt-4 border-t border-gray-100">
                    <span className="text-indigo-600 font-bold">
                      {item === 1
                        ? "$89.99"
                        : item === 2
                        ? "$129.99"
                        : "$69.99"}
                    </span>
                    <button className="text-indigo-600 hover:text-indigo-800 font-medium flex items-center">
                      Enroll Now <ChevronRight className="h-4 w-4 ml-1" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="text-center mt-12">
            <button className="border-2 border-indigo-600 text-indigo-600 px-8 py-3 rounded-full font-medium hover:bg-indigo-50 transition-all">
              View All Courses
            </button>
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section className="py-20 bg-indigo-600 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">What Our Students Say</h2>
            <p className="text-xl opacity-90 max-w-2xl mx-auto">
              Hear from our students about their learning experience
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {[1, 2, 3].map((item) => (
              <div
                key={item}
                className="bg-white bg-opacity-10 p-8 rounded-xl backdrop-blur-sm"
              >
                <div className="flex items-center mb-6">
                  <div className="h-12 w-12 rounded-full overflow-hidden mr-4">
                    <img
                      src={`https://randomuser.me/api/portraits/${
                        item === 1 ? "women" : item === 2 ? "men" : "women"
                      }/${item}2.jpg`}
                      alt="Student"
                      className="w-full h-full object-cover"
                    />
                  </div>
                  <div>
                    <h4 className="font-bold">
                      {item === 1
                        ? "Sarah Johnson"
                        : item === 2
                        ? "Michael Chen"
                        : "Emma Rodriguez"}
                    </h4>
                    <p className="text-sm opacity-80">
                      {item === 1
                        ? "UI Designer"
                        : item === 2
                        ? "Web Developer"
                        : "Marketing Specialist"}
                    </p>
                  </div>
                </div>
                <p className="mb-6">
                  {item === 1
                    ? "The courses transformed my design skills. The instructors are knowledgeable and the platform is easy to use."
                    : item === 2
                    ? "I landed my dream job after completing the Full Stack Development course. The hands-on projects were incredibly valuable."
                    : "The digital marketing course gave me practical skills I could apply immediately to grow my business."}
                </p>
                <div className="flex text-yellow-400">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <Star key={star} className="h-5 w-5 fill-current" />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold mb-4">
              Simple, Transparent Pricing
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Choose the plan that works best for your learning goals
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            <div className="bg-white p-8 rounded-xl shadow-sm border border-gray-200">
              <h3 className="text-xl font-bold mb-2">Basic</h3>
              <p className="text-gray-600 mb-6">Perfect for casual learners</p>
              <div className="mb-8">
                <span className="text-4xl font-bold">$19</span>
                <span className="text-gray-600">/month</span>
              </div>
              <ul className="space-y-3 mb-8">
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Access to 100+ courses</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Basic support</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Community access</span>
                </li>
                <li className="flex items-center text-gray-400">
                  <Check className="h-5 w-5 mr-2" />
                  <span>No certificates</span>
                </li>
                <li className="flex items-center text-gray-400">
                  <Check className="h-5 w-5 mr-2" />
                  <span>No premium courses</span>
                </li>
              </ul>
              <button className="w-full border-2 border-indigo-600 text-indigo-600 px-6 py-3 rounded-full font-medium hover:bg-indigo-50 transition-all">
                Get Started
              </button>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-lg border-2 border-indigo-600 relative">
              <div className="absolute top-0 right-0 bg-indigo-600 text-white text-xs font-bold px-3 py-1 rounded-bl-lg rounded-tr-lg">
                MOST POPULAR
              </div>
              <h3 className="text-xl font-bold mb-2">Pro</h3>
              <p className="text-gray-600 mb-6">For serious learners</p>
              <div className="mb-8">
                <span className="text-4xl font-bold">$49</span>
                <span className="text-gray-600">/month</span>
              </div>
              <ul className="space-y-3 mb-8">
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Access to all courses</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Priority support</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Downloadable resources</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Completion certificates</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Premium courses included</span>
                </li>
              </ul>
              <button className="w-full bg-indigo-600 text-white px-6 py-3 rounded-full font-medium hover:bg-indigo-700 transition-all">
                Get Started
              </button>
            </div>

            <div className="bg-white p-8 rounded-xl shadow-sm border border-gray-200">
              <h3 className="text-xl font-bold mb-2">Enterprise</h3>
              <p className="text-gray-600 mb-6">For teams and organizations</p>
              <div className="mb-8">
                <span className="text-4xl font-bold">$99</span>
                <span className="text-gray-600">/month</span>
              </div>
              <ul className="space-y-3 mb-8">
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Everything in Pro</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Team dashboard</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Advanced analytics</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Custom learning paths</span>
                </li>
                <li className="flex items-center">
                  <Check className="h-5 w-5 text-green-500 mr-2" />
                  <span>Dedicated account manager</span>
                </li>
              </ul>
              <button className="w-full border-2 border-indigo-600 text-indigo-600 px-6 py-3 rounded-full font-medium hover:bg-indigo-50 transition-all">
                Contact Sales
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-indigo-600 text-white">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-bold mb-6">Ready to Start Learning?</h2>
          <p className="text-xl opacity-90 mb-8">
            Join thousands of students advancing their careers with our courses
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <button className="bg-white text-indigo-600 px-8 py-3 rounded-full font-medium hover:bg-gray-100 transition-all flex items-center">
              Get Started <ChevronRight className="ml-2 h-5 w-5" />
            </button>
            <button className="border-2 border-white text-white px-8 py-3 rounded-full font-medium hover:bg-white hover:bg-opacity-10 transition-all">
              Browse Courses
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-gray-300 py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-4 gap-12">
            <div>
              <div className="flex items-center mb-6">
                <GraduationCap className="h-8 w-8 text-indigo-400" />
                <span className="ml-2 text-2xl font-bold text-white">
                  {brandName}
                </span>
              </div>
              <p className="mb-6">
                Empowering learners worldwide with accessible, high-quality
                education.
              </p>
              <div className="flex space-x-4">
                <a href="#" className="text-gray-400 hover:text-white">
                  <svg
                    className="h-6 w-6"
                    fill="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path d="M24 4.557c-.883.392-1.832.656-2.828.775 1.017-.609 1.798-1.574 2.165-2.724-.951.564-2.005.974-3.127 1.195-.897-.957-2.178-1.555-3.594-1.555-3.179 0-5.515 2.966-4.797 6.045-4.091-.205-7.719-2.165-10.148-5.144-1.29 2.213-.669 5.108 1.523 6.574-.806-.026-1.566-.247-2.229-.616-.054 2.281 1.581 4.415 3.949 4.89-.693.188-1.452.232-2.224.084.626 1.956 2.444 3.379 4.6 3.419-2.07 1.623-4.678 2.348-7.29 2.04 2.179 1.397 4.768 2.212 7.548 2.212 9.142 0 14.307-7.721 13.995-14.646.962-.695 1.797-1.562 2.457-2.549z" />
                  </svg>
                </a>
                <a href="#" className="text-gray-400 hover:text-white">
                  <svg
                    className="h-6 w-6"
                    fill="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z" />
                  </svg>
                </a>
                <a href="#" className="text-gray-400 hover:text-white">
                  <svg
                    className="h-6 w-6"
                    fill="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z" />
                  </svg>
                </a>
              </div>
            </div>

            <div>
              <h3 className="text-white font-bold text-lg mb-6">Company</h3>
              <ul className="space-y-3">
                <li>
                  <a href="#" className="hover:text-white">
                    About Us
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Careers
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Blog
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Press
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Contact
                  </a>
                </li>
              </ul>
            </div>

            <div>
              <h3 className="text-white font-bold text-lg mb-6">Resources</h3>
              <ul className="space-y-3">
                <li>
                  <a href="#" className="hover:text-white">
                    Help Center
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Tutorials
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Community
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Webinars
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Feedback
                  </a>
                </li>
              </ul>
            </div>

            <div>
              <h3 className="text-white font-bold text-lg mb-6">Legal</h3>
              <ul className="space-y-3">
                <li>
                  <a href="#" className="hover:text-white">
                    Privacy Policy
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Terms of Service
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Cookie Policy
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    GDPR
                  </a>
                </li>
                <li>
                  <a href="#" className="hover:text-white">
                    Accessibility
                  </a>
                </li>
              </ul>
            </div>
          </div>

          <div className="border-t border-gray-800 mt-12 pt-8 text-center">
            <p>
              &copy; {new Date().getFullYear()} {brandName}. All rights
              reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Home;
