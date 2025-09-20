"use client";
import React, { useState } from "react";
import {
  BookOpen,
  User,
  Bell,
  Search,
  Menu,
  X,
  GraduationCap,
  Calendar,
  MessageCircle,
  Settings,
  ChevronDown,
  Award,
  BarChart3,
  Users,
  PlayCircle,
  Book,
} from "lucide-react";
import { brandName } from "@/app/contants";
import { useDispatch, useSelector } from "react-redux";
import { logout } from "@/lib/store/features/authSlice";
import Link from "next/link";

const UserNavbar = () => {
  const {
    status,
    error,
    loginMethod,
    phoneNumber,
    otpSent,
    isAuthenticated,
    user,
  } = useSelector((state) => state.auth);
  const dispatch = useDispatch(); // Add this line

  const handleLogout = () => {
    console.log("herer");
    dispatch(logout()); // Dispatch the logout action
  };

  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);

  const toggleMenu = () => setIsMenuOpen(!isMenuOpen);
  const toggleProfile = () => setIsProfileOpen(!isProfileOpen);
  const toggleNotifications = () =>
    setIsNotificationsOpen(!isNotificationsOpen);

  return (
    <nav className="bg-white/80 backdrop-blur-lg border-b border-gray-200/50 sticky top-0 z-50 shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Brand */}
          <Link href={"/user/dashboard"}>
            <div className="flex items-center space-x-3">
              <div className="flex-shrink-0 flex items-center">
                <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
                  <GraduationCap className="h-6 w-6 text-white" />
                </div>
                <span className="ml-3 text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  {brandName}
                </span>
              </div>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:block">
            <div className="ml-10 flex items-baseline space-x-1">
              {/* <NavItem icon={BookOpen} text="Dashboard" active /> */}
              <NavItem icon={PlayCircle} text="Courses" />
              <NavItem icon={Calendar} text="Schedule" />
              <NavItem icon={Award} text="Achievements" />
              <NavItem icon={Users} text="Community" />
              {/* <NavItem icon={BarChart3} text="Analytics" /> */}
            </div>
          </div>

          {/* Search Bar */}
          <div className="hidden md:block flex-1 max-w-md mx-8">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search courses, assignments..."
                className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-xl bg-gray-50/50 focus:bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all duration-200 text-sm"
              />
            </div>
          </div>

          {/* Right side items */}
          <div className="flex items-center space-x-4">
            {/* Notifications */}
            <div className="relative">
              <button
                onClick={toggleNotifications}
                className="relative p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors duration-200"
              >
                <Bell className="h-5 w-5" />
                <span className="absolute -top-1 -right-1 h-4 w-4 bg-red-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-xs font-medium">3</span>
                </span>
              </button>

              {isNotificationsOpen && (
                <div className="absolute right-0 mt-2 w-80 bg-white rounded-xl shadow-lg border border-gray-200 py-2 z-50">
                  <div className="px-4 py-2 border-b border-gray-100">
                    <h3 className="font-semibold text-gray-900">
                      Notifications
                    </h3>
                  </div>
                  <NotificationItem
                    title="New assignment posted"
                    message="Mathematics Quiz 3 is now available"
                    time="2 mins ago"
                    unread
                  />
                  <NotificationItem
                    title="Class reminder"
                    message="Physics lecture starts in 30 minutes"
                    time="25 mins ago"
                    unread
                  />
                  <NotificationItem
                    title="Grade updated"
                    message="Your Chemistry lab report has been graded"
                    time="1 hour ago"
                  />
                </div>
              )}
            </div>

            {/* Messages */}
            <button className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors duration-200">
              <MessageCircle className="h-5 w-5" />
            </button>

            {/* Profile Dropdown */}
            <div className="relative">
              <button
                onClick={toggleProfile}
                className="flex items-center space-x-2 p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors duration-200"
              >
                <div className="w-8 h-8 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center">
                  <User className="h-4 w-4 text-white" />
                </div>
                <ChevronDown className="h-4 w-4" />
              </button>

              {isProfileOpen && (
                <div className="absolute right-0 mt-2 w-56 bg-white rounded-xl shadow-lg border border-gray-200 py-2 z-50">
                  <div className="px-4 py-3 border-b border-gray-100">
                    <p className="text-sm font-medium text-gray-900">
                      {user?.name || "John Doe"}
                    </p>
                    <p className="text-xs text-gray-500">
                      {user?.email || "john.doe@university.edu"}
                    </p>
                  </div>
                  <ProfileMenuItem icon={User} text="Profile" />
                  <Link href={"/user/mycourses"}>
                    <ProfileMenuItem icon={Book} text="My Courses" />
                  </Link>
                  <ProfileMenuItem icon={Settings} text="Settings" />
                  <ProfileMenuItem icon={Award} text="Certificates" />
                  <div className="border-t border-gray-100 mt-2 pt-2">
                    <ProfileMenuItem
                      text="Sign out"
                      clickmethod={handleLogout}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Mobile menu button */}
            <button
              onClick={toggleMenu}
              className="md:hidden p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors duration-200"
            >
              {isMenuOpen ? (
                <X className="h-5 w-5" />
              ) : (
                <Menu className="h-5 w-5" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      {isMenuOpen && (
        <div className="md:hidden bg-white/95 backdrop-blur-sm border-t border-gray-200">
          <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
            <MobileNavItem icon={BookOpen} text="Dashboard" active />
            <MobileNavItem icon={PlayCircle} text="Courses" />
            <MobileNavItem icon={Calendar} text="Schedule" />
            <MobileNavItem icon={Award} text="Achievements" />
            <MobileNavItem icon={Users} text="Community" />
            <MobileNavItem icon={BarChart3} text="Analytics" />
          </div>
          <div className="px-4 py-3 border-t border-gray-200">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search courses, assignments..."
                className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-xl bg-gray-50/50 focus:bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all duration-200 text-sm"
              />
            </div>
          </div>
        </div>
      )}
    </nav>
  );
};

const NavItem = ({ icon: Icon, text, active = false }) => (
  <button
    className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
      active
        ? "bg-blue-50 text-blue-600 shadow-sm"
        : "text-gray-700 hover:text-gray-900 hover:bg-gray-50"
    }`}
  >
    <Icon className="h-4 w-4" />
    <span>{text}</span>
  </button>
);

const MobileNavItem = ({ icon: Icon, text, active = false }) => (
  <button
    className={`flex items-center space-x-3 w-full px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
      active
        ? "bg-blue-50 text-blue-600 shadow-sm"
        : "text-gray-700 hover:text-gray-900 hover:bg-gray-50"
    }`}
  >
    <Icon className="h-5 w-5" />
    <span>{text}</span>
  </button>
);

const NotificationItem = ({ title, message, time, unread = false }) => (
  <div
    className={`px-4 py-3 hover:bg-gray-50 cursor-pointer transition-colors duration-200 ${
      unread ? "bg-blue-50/50" : ""
    }`}
  >
    <div className="flex items-start space-x-3">
      {unread && (
        <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
      )}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-900">{title}</p>
        <p className="text-xs text-gray-500 mt-1">{message}</p>
        <p className="text-xs text-gray-400 mt-1">{time}</p>
      </div>
    </div>
  </div>
);

const ProfileMenuItem = ({ icon: Icon, text, clickmethod }) => (
  <button
    onClick={() => clickmethod()}
    className="flex items-center space-x-3 w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 hover:text-gray-900 transition-colors duration-200"
  >
    {Icon && <Icon className="h-4 w-4" />}
    <span>{text}</span>
  </button>
);

export default UserNavbar;
