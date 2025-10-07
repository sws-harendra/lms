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
  ChevronDown,
  Award,
  Users,
  PlayCircle,
  LogOut,
  Settings
} from "lucide-react";
import { useDispatch, useSelector } from "react-redux";
import { logout } from "@/lib/store/features/authSlice";
import Link from "next/link";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";
import { useTranslation } from "@/contexts/TranslationContext";
import LanguageSelector from "./LanguageSelector";

const UserNavbar = () => {
  const { t } = useTranslation();
  const dispatch = useDispatch();
  const { user } = useSelector((state) => state.auth);
  const { settings } = useSelector((state) => state.appSettings);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);

  const handleLogout = () => {
    dispatch(logout());
  };

  const toggleMenu = () => setIsMenuOpen(!isMenuOpen);
  const toggleProfile = () => setIsProfileOpen(!isProfileOpen);

  return (
    <nav className="bg-white/80 backdrop-blur-lg border-b border-gray-200/50 sticky top-0 z-50 shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Brand */}
          <Link href={"/"}>
            <div className="flex items-center space-x-3">
              <div className="flex-shrink-0 flex items-center">
                <div className="w-10 h-10 bg-gradient-to-br rounded-xl flex items-center justify-center shadow-lg">
                  <GraduationCap className="h-6 w-6" />
                </div>
                <span className="ml-3 text-black text-xl font-bold">
                  {settings?.platformName}.
                </span>
              </div>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:block">
            <div className="ml-10 flex items-baseline space-x-1">
              <Link href={"/user/dashboard"}>
                <NavItem icon={PlayCircle} text={t('Courses')} />
              </Link>
              <Link href={"/user/mycourses"}>
                <NavItem icon={BookOpen} text={t('My Courses')} />
              </Link>
              <NavItem icon={Award} text={t('Achievements')} />
              <NavItem icon={Users} text={t('Community')} />
            </div>
          </div>

          {/* Search Bar */}
          <div className="hidden md:block flex-1 max-w-md mx-8">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder={t('Search courses, assignments...')}
                className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-xl bg-gray-50/50 focus:bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all duration-200 text-sm"
              />
            </div>
          </div>

          {/* Right side items */}
          <div className="flex items-center space-x-4">
            {/* Language Selector */}
            <LanguageSelector />

            {/* Profile Dropdown */}
            <div className="relative">
              <button
                onClick={toggleProfile}
                className="flex items-center space-x-2 p-1 rounded-full hover:bg-gray-100 transition-colors duration-200"
              >
                <div className="w-8 h-8 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center">
                  {user?.profileImage ? (
                    <img 
                      src={getMediaUrl(user.profileImage)} 
                      className="w-full h-full rounded-full object-cover"
                      alt={user?.name}
                    />
                  ) : (
                    <User className="h-4 w-4 text-white" />
                  )}
                </div>
              </button>

              {isProfileOpen && (
                <div className="absolute right-0 mt-2 w-56 bg-white rounded-xl shadow-lg border border-gray-200 py-2 z-50">
                  <div className="px-4 py-3 border-b border-gray-100">
                    <span className="block text-sm font-medium text-gray-900">
                      {user?.name || t('User')}
                    </span>
                    <span className="block text-xs text-gray-500">
                      {user?.email}
                    </span>
                  </div>
                  <Link href="/user/profile">
                    <div className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                      <User className="mr-3 h-5 w-5 text-gray-400" />
                      {t('Profile')}
                    </div>
                  </Link>
                  <Link href="/user/settings">
                    <div className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
                      <Settings className="mr-3 h-5 w-5 text-gray-400" />
                      {t('Settings')}
                    </div>
                  </Link>
                  <div className="border-t border-gray-100 mt-2 pt-2">
                    <button
                      onClick={handleLogout}
                      className="flex w-full items-center px-4 py-2 text-left text-sm text-red-600 hover:bg-gray-100"
                    >
                      <LogOut className="mr-3 h-5 w-5 text-red-400" />
                      {t('Logout')}
                    </button>
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
            <MobileNavItem icon={PlayCircle} text={t('Courses')} href="/user/dashboard" />
            <MobileNavItem icon={BookOpen} text={t('My Courses')} href="/user/mycourses" />
            <MobileNavItem icon={Award} text={t('Achievements')} />
            <MobileNavItem icon={Users} text={t('Community')} />
          </div>
          <div className="px-4 py-3 border-t border-gray-200">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder={t('Search courses, assignments...')}
                className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-xl bg-gray-50/50 focus:bg-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all duration-200 text-sm"
              />
            </div>
          </div>
        </div>
      )}
    </nav>
  );
};

const NavItem = ({ icon: Icon, text, active = false, ...props }) => (
  <button
    className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
      active
        ? "bg-blue-50 text-blue-600 shadow-sm"
        : "text-gray-700 hover:text-gray-900 hover:bg-gray-50"
    }`}
    {...props}
  >
    <Icon className="h-4 w-4" />
    <span>{text}</span>
  </button>
);

const MobileNavItem = ({ icon: Icon, text, active = false, href = "#" }) => (
  <Link
    href={href}
    className={`flex items-center space-x-3 w-full px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
      active
        ? "bg-blue-50 text-blue-600 shadow-sm"
        : "text-gray-700 hover:text-gray-900 hover:bg-gray-50"
    }`}
  >
    <Icon className="h-5 w-5" />
    <span>{text}</span>
  </Link>
);

export default UserNavbar;