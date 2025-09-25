"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  X,
  Plus,
  Trash2,
  Upload,
  Video,
  FileText,
  GripVertical,
} from "lucide-react";
import {
  createCourse,
  getAllCategories,
} from "@/lib/store/features/courseSlice";
import { useDispatch, useSelector } from "react-redux";

export default function EnhancedCourseForm() {
  const dispatch = useDispatch();
  const { categories, status } = useSelector((state) => state.course);
  let isLoading = status == "loading";
  useEffect(() => {
    // Fetch categories from backend if not already loaded
    dispatch(getAllCategories());
  }, []); // dispatch(fetchCategories());
  // Basic course info
  const [title, setTitle] = useState("");
  const [slug, setSlug] = useState("");
  const [description, setDescription] = useState("");
  const [thumbnail, setThumbnail] = useState(null);
  const [category, setCategory] = useState("");
  const [level, setLevel] = useState("beginner");
  const [language, setLanguage] = useState("English");

  // Pricing
  const [price, setPrice] = useState("");
  const [discountPrice, setDiscountPrice] = useState("");
  const [isFree, setIsFree] = useState(false);

  // Settings
  const [isPublished, setIsPublished] = useState(false);
  const [certificateEnabled, setCertificateEnabled] = useState(false);

  // Tags
  const [tags, setTags] = useState([]);
  const [currentTag, setCurrentTag] = useState("");

  // Requirements and outcomes
  const [requirements, setRequirements] = useState([""]);
  const [whatYouWillLearn, setWhatYouWillLearn] = useState([""]);

  // Sections and lessons
  const [sections, setSections] = useState([
    {
      title: "",
      description: "",
      order: 0,
      lessons: [
        {
          title: "",
          videoUrl: "",
          videoFile: null,
          duration: "",
          description: "",
          isFree: false,
          order: 0,
        },
      ],
      resources: [],
    },
  ]);

  // Auto-generate slug from title
  const generateSlug = (title) => {
    return title
      .toLowerCase()
      .replace(/[^a-z0-9 -]/g, "")
      .replace(/\s+/g, "-")
      .replace(/-+/g, "-")
      .trim();
  };

  const handleTitleChange = (value) => {
    setTitle(value);
    if (!slug) {
      setSlug(generateSlug(value));
    }
  };

  // Tag management
  const addTag = () => {
    if (currentTag.trim() && !tags.includes(currentTag.trim())) {
      setTags([...tags, currentTag.trim()]);
      setCurrentTag("");
    }
  };

  const removeTag = (tagToRemove) => {
    setTags(tags.filter((tag) => tag !== tagToRemove));
  };

  // Requirements management
  const addRequirement = () => {
    setRequirements([...requirements, ""]);
  };

  const updateRequirement = (index, value) => {
    const newRequirements = [...requirements];
    newRequirements[index] = value;
    setRequirements(newRequirements);
  };

  const removeRequirement = (index) => {
    if (requirements.length > 1) {
      setRequirements(requirements.filter((_, i) => i !== index));
    }
  };

  // Learning outcomes management
  const addLearningOutcome = () => {
    setWhatYouWillLearn([...whatYouWillLearn, ""]);
  };

  const updateLearningOutcome = (index, value) => {
    const newOutcomes = [...whatYouWillLearn];
    newOutcomes[index] = value;
    setWhatYouWillLearn(newOutcomes);
  };

  const removeLearningOutcome = (index) => {
    if (whatYouWillLearn.length > 1) {
      setWhatYouWillLearn(whatYouWillLearn.filter((_, i) => i !== index));
    }
  };

  // Section management
  const addSection = () => {
    setSections([
      ...sections,
      {
        title: "",
        description: "",
        order: sections.length,
        lessons: [
          {
            title: "",
            videoUrl: "",
            videoFile: null,
            duration: "",
            description: "",
            isFree: false,
            order: 0,
          },
        ],
        resources: [],
      },
    ]);
  };

  const removeSection = (sectionIndex) => {
    if (sections.length > 1) {
      setSections(sections.filter((_, index) => index !== sectionIndex));
    }
  };

  const updateSectionField = (sectionIndex, field, value) => {
    const newSections = [...sections];
    newSections[sectionIndex][field] = value;
    setSections(newSections);
  };

  // Lesson management
  const addLesson = (sectionIndex) => {
    const newSections = [...sections];
    newSections[sectionIndex].lessons.push({
      title: "",
      videoUrl: "",
      videoFile: null,
      duration: "",
      description: "",
      isFree: false,
      order: newSections[sectionIndex].lessons.length,
    });
    setSections(newSections);
  };

  const removeLesson = (sectionIndex, lessonIndex) => {
    const newSections = [...sections];
    if (newSections[sectionIndex].lessons.length > 1) {
      newSections[sectionIndex].lessons.splice(lessonIndex, 1);
      setSections(newSections);
    }
  };

  const handleLessonChange = (sectionIndex, lessonIndex, field, value) => {
    const newSections = [...sections];
    newSections[sectionIndex].lessons[lessonIndex][field] = value;
    setSections(newSections);
  };

  // Resource management
  const addResource = (sectionIndex, type) => {
    const newSections = [...sections];
    newSections[sectionIndex].resources.push({
      type,
      title: "",
      url: "",
      content: "",
      isFree: false,
      order: newSections[sectionIndex].resources.length,
    });
    setSections(newSections);
  };

  const removeResource = (sectionIndex, resourceIndex) => {
    const newSections = [...sections];
    newSections[sectionIndex].resources.splice(resourceIndex, 1);
    setSections(newSections);
  };

  const handleResourceChange = (sectionIndex, resourceIndex, field, value) => {
    const newSections = [...sections];
    newSections[sectionIndex].resources[resourceIndex][field] = value;
    setSections(newSections);
  };

  // Form submission
  // Form submission - ONLY CHANGE THE ARRAY HANDLING
  const handleSubmit = async (e) => {
    e.preventDefault();

    const formData = new FormData();

    // Basic course data - KEEP EVERYTHING ELSE THE SAME
    formData.append("title", title);
    formData.append("slug", slug);
    formData.append("description", description);
    formData.append("category", category);
    formData.append("level", level);
    formData.append("language", language);
    formData.append("price", isFree ? "0" : price);
    formData.append("discountPrice", discountPrice || "0");
    formData.append("isFree", isFree.toString());
    formData.append("isPublished", isPublished.toString());
    formData.append("certificateEnabled", certificateEnabled.toString());

    // ✅ FIX: Append arrays WITHOUT JSON.stringify()
    // Just append each item individually with the same field name
    tags.forEach((tag) => {
      formData.append("tags", tag); // Simple string, not JSON
    });

    requirements
      .filter((r) => r.trim())
      .forEach((req) => {
        formData.append("requirements", req); // Simple string
      });

    whatYouWillLearn
      .filter((w) => w.trim())
      .forEach((item) => {
        formData.append("whatYouWillLearn", item); // Simple string
      });

    // Thumbnail - KEEP THE SAME
    if (thumbnail) formData.append("thumbnail", thumbnail);

    // Lesson videos - KEEP THE SAME
    sections.forEach((section) => {
      section.lessons.forEach((lesson) => {
        if (lesson.videoFile) {
          formData.append("lessonVideos", lesson.videoFile);
        }
      });
    });

    // Sections data - KEEP JSON.stringify() for complex objects
    const sectionsData = sections.map((section) => ({
      title: section.title,
      description: section.description,
      order: section.order,
      lessons: section.lessons.map((lesson) => ({
        title: lesson.title,
        videoUrl: lesson.videoUrl,
        duration: lesson.duration ? parseInt(lesson.duration) : 0,
        description: lesson.description,
        isFree: lesson.isFree,
        order: lesson.order,
      })),
      resources: section.resources,
    }));

    formData.append("sections", JSON.stringify(sectionsData)); // This is correct for complex objects

    console.log("Form data ready for submission:");

    // Debug: Log what's being sent
    for (let [key, value] of formData.entries()) {
      console.log(key, value);
    }

    dispatch(createCourse(formData));
  };
  return (
    <div className="mx-auto p-6 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-2xl font-bold">
            Create New Course
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-8">
            <Tabs defaultValue="basic" className="w-full">
              <TabsList className="grid w-full grid-cols-4">
                <TabsTrigger value="basic">Basic Info</TabsTrigger>
                <TabsTrigger value="content">Content</TabsTrigger>
                <TabsTrigger value="requirements">Requirements</TabsTrigger>
                <TabsTrigger value="settings">Settings</TabsTrigger>
              </TabsList>

              {/* Basic Information Tab */}
              <TabsContent value="basic" className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="title">Course Title *</Label>
                    <Input
                      id="title"
                      value={title}
                      onChange={(e) => handleTitleChange(e.target.value)}
                      placeholder="Enter course title"
                      required
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="slug">URL Slug *</Label>
                    <Input
                      id="slug"
                      value={slug}
                      onChange={(e) => setSlug(e.target.value)}
                      placeholder="course-url-slug"
                      required
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="description">Course Description *</Label>
                  <Textarea
                    id="description"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="Describe what students will learn in this course"
                    className="min-h-[120px]"
                    required
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="category">Category *</Label>
                    <Select value={category} onValueChange={setCategory}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select category" />
                      </SelectTrigger>
                      <SelectContent>
                        {categories.map((cat) => (
                          <SelectItem key={cat._id} value={cat._id}>
                            {cat.name}
                          </SelectItem>
                        ))}
                        {/* <SelectItem value="programming">Programming</SelectItem>
                        <SelectItem value="design">Design</SelectItem>
                        <SelectItem value="business">Business</SelectItem>
                        <SelectItem value="marketing">Marketing</SelectItem> */}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="level">Level</Label>
                    <Select value={level} onValueChange={setLevel}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="beginner">Beginner</SelectItem>
                        <SelectItem value="intermediate">
                          Intermediate
                        </SelectItem>
                        <SelectItem value="advanced">Advanced</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="language">Language</Label>
                    <Select value={language} onValueChange={setLanguage}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="English">English</SelectItem>
                        <SelectItem value="Spanish">Spanish</SelectItem>
                        <SelectItem value="French">French</SelectItem>
                        <SelectItem value="German">German</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-4">
                  <Label>Course Thumbnail *</Label>
                  <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-gray-400 transition-colors">
                    <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                    <div className="space-y-2">
                      <Label
                        htmlFor="thumbnail"
                        className="cursor-pointer text-sm font-medium text-blue-600 hover:text-blue-500"
                      >
                        Click to upload thumbnail
                      </Label>
                      <p className="text-sm text-gray-500">
                        PNG, JPG up to 2MB
                      </p>
                      <input
                        id="thumbnail"
                        type="file"
                        accept="image/*"
                        onChange={(e) => setThumbnail(e.target.files[0])}
                        className="hidden"
                      />
                    </div>
                    {thumbnail && (
                      <p className="mt-2 text-sm text-green-600">
                        Selected: {thumbnail.name}
                      </p>
                    )}
                  </div>
                </div>

                <div className="space-y-4">
                  <Label>Tags</Label>
                  <div className="flex gap-2">
                    <Input
                      value={currentTag}
                      onChange={(e) => setCurrentTag(e.target.value)}
                      placeholder="Add a tag"
                      onKeyPress={(e) =>
                        e.key === "Enter" && (e.preventDefault(), addTag())
                      }
                    />
                    <Button type="button" onClick={addTag} variant="outline">
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {tags.map((tag, index) => (
                      <Badge
                        key={index}
                        variant="secondary"
                        className="flex items-center gap-1"
                      >
                        {tag}
                        <X
                          className="h-3 w-3 cursor-pointer hover:text-red-500"
                          onClick={() => removeTag(tag)}
                        />
                      </Badge>
                    ))}
                  </div>
                </div>

                <Separator />

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="price">Price ($) *</Label>
                    <Input
                      id="price"
                      type="number"
                      value={price}
                      onChange={(e) => setPrice(e.target.value)}
                      placeholder="99.00"
                      min="0"
                      step="0.01"
                      disabled={isFree}
                      required={!isFree}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="discountPrice">Discount Price ($)</Label>
                    <Input
                      id="discountPrice"
                      type="number"
                      value={discountPrice}
                      onChange={(e) => setDiscountPrice(e.target.value)}
                      placeholder="79.00"
                      min="0"
                      step="0.01"
                      disabled={isFree}
                    />
                  </div>

                  <div className="flex items-center space-x-2 pt-8">
                    <Checkbox
                      id="isFree"
                      checked={isFree}
                      onCheckedChange={setIsFree}
                    />
                    <Label htmlFor="isFree">Free Course</Label>
                  </div>
                </div>
              </TabsContent>

              {/* Content Tab */}
              <TabsContent value="content" className="space-y-6">
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold">Course Sections</h3>
                    <Button
                      type="button"
                      onClick={addSection}
                      variant="outline"
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Add Section
                    </Button>
                  </div>

                  {sections.map((section, sIdx) => (
                    <Card key={sIdx} className="border-2">
                      <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <GripVertical className="h-5 w-5 text-gray-400" />
                            <CardTitle className="text-lg">
                              Section {sIdx + 1}
                            </CardTitle>
                          </div>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => removeSection(sIdx)}
                            disabled={sections.length === 1}
                            className="text-red-600 hover:text-red-700 hover:bg-red-50"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label>Section Title *</Label>
                            <Input
                              value={section.title}
                              onChange={(e) =>
                                updateSectionField(
                                  sIdx,
                                  "title",
                                  e.target.value
                                )
                              }
                              placeholder="Introduction to..."
                              required
                            />
                          </div>
                          <div className="space-y-2">
                            <Label>Section Description</Label>
                            <Input
                              value={section.description}
                              onChange={(e) =>
                                updateSectionField(
                                  sIdx,
                                  "description",
                                  e.target.value
                                )
                              }
                              placeholder="Brief description of this section"
                            />
                          </div>
                        </div>

                        <div className="space-y-4">
                          <div className="flex items-center justify-between">
                            <h4 className="font-medium">Lessons</h4>
                            <Button
                              type="button"
                              onClick={() => addLesson(sIdx)}
                              variant="outline"
                              size="sm"
                            >
                              <Plus className="h-4 w-4 mr-2" />
                              Add Lesson
                            </Button>
                          </div>

                          {section.lessons.map((lesson, lIdx) => (
                            <Card key={lIdx} className="border">
                              <CardContent className="pt-4">
                                <div className="space-y-4">
                                  <div className="flex items-center justify-between">
                                    <h5 className="font-medium text-sm">
                                      Lesson {lIdx + 1}
                                    </h5>
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => removeLesson(sIdx, lIdx)}
                                      disabled={section.lessons.length === 1}
                                      className="text-red-600 hover:text-red-700"
                                    >
                                      <X className="h-4 w-4" />
                                    </Button>
                                  </div>

                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div className="space-y-2">
                                      <Label>Lesson Title *</Label>
                                      <Input
                                        value={lesson.title}
                                        onChange={(e) =>
                                          handleLessonChange(
                                            sIdx,
                                            lIdx,
                                            "title",
                                            e.target.value
                                          )
                                        }
                                        placeholder="Lesson title"
                                        required
                                      />
                                    </div>
                                    <div className="space-y-2">
                                      <Label>Duration (minutes)</Label>
                                      <Input
                                        type="number"
                                        value={lesson.duration}
                                        onChange={(e) =>
                                          handleLessonChange(
                                            sIdx,
                                            lIdx,
                                            "duration",
                                            e.target.value
                                          )
                                        }
                                        placeholder="15"
                                        min="1"
                                      />
                                    </div>
                                  </div>

                                  <div className="space-y-2">
                                    <Label>Lesson Description</Label>
                                    <Textarea
                                      value={lesson.description}
                                      onChange={(e) =>
                                        handleLessonChange(
                                          sIdx,
                                          lIdx,
                                          "description",
                                          e.target.value
                                        )
                                      }
                                      placeholder="What will students learn in this lesson?"
                                      className="min-h-[80px]"
                                    />
                                  </div>

                                  <div className="space-y-2">
                                    <Label>Video URL</Label>
                                    <Input
                                      value={lesson.videoUrl}
                                      onChange={(e) =>
                                        handleLessonChange(
                                          sIdx,
                                          lIdx,
                                          "videoUrl",
                                          e.target.value
                                        )
                                      }
                                      placeholder="https://youtube.com/..."
                                    />
                                  </div>

                                  <div className="space-y-2">
                                    <Label>Or Upload Video File</Label>
                                    <div className="flex items-center space-x-2">
                                      <input
                                        type="file"
                                        accept="video/*"
                                        onChange={(e) =>
                                          handleLessonChange(
                                            sIdx,
                                            lIdx,
                                            "videoFile",
                                            e.target.files[0]
                                          )
                                        }
                                        className="hidden"
                                        id={`video-${sIdx}-${lIdx}`}
                                      />
                                      <Label
                                        htmlFor={`video-${sIdx}-${lIdx}`}
                                        className="cursor-pointer flex items-center gap-2 px-4 py-2 border rounded-md hover:bg-gray-50"
                                      >
                                        <Video className="h-4 w-4" />
                                        Choose Video
                                      </Label>
                                      {lesson.videoFile && (
                                        <span className="text-sm text-green-600">
                                          {lesson.videoFile.name}
                                        </span>
                                      )}
                                    </div>
                                  </div>

                                  <div className="flex items-center space-x-2">
                                    <Checkbox
                                      id={`lesson-free-${sIdx}-${lIdx}`}
                                      checked={lesson.isFree}
                                      onCheckedChange={(checked) =>
                                        handleLessonChange(
                                          sIdx,
                                          lIdx,
                                          "isFree",
                                          checked
                                        )
                                      }
                                    />
                                    <Label
                                      htmlFor={`lesson-free-${sIdx}-${lIdx}`}
                                    >
                                      Free Preview
                                    </Label>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>

                        <Separator />

                        <div className="space-y-4">
                          <div className="flex items-center justify-between">
                            <h4 className="font-medium">
                              Additional Resources
                            </h4>
                            <div className="flex gap-2">
                              <Button
                                type="button"
                                onClick={() => addResource(sIdx, "pdf")}
                                variant="outline"
                                size="sm"
                              >
                                <FileText className="h-4 w-4 mr-2" />
                                PDF
                              </Button>
                              <Button
                                type="button"
                                onClick={() => addResource(sIdx, "quiz")}
                                variant="outline"
                                size="sm"
                              >
                                Quiz
                              </Button>
                            </div>
                          </div>

                          {section.resources.map((resource, rIdx) => (
                            <Card key={rIdx} className="border">
                              <CardContent className="pt-4">
                                <div className="space-y-4">
                                  <div className="flex items-center justify-between">
                                    <Badge variant="secondary">
                                      {resource.type.toUpperCase()}
                                    </Badge>
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => removeResource(sIdx, rIdx)}
                                      className="text-red-600"
                                    >
                                      <X className="h-4 w-4" />
                                    </Button>
                                  </div>

                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <Input
                                      value={resource.title}
                                      onChange={(e) =>
                                        handleResourceChange(
                                          sIdx,
                                          rIdx,
                                          "title",
                                          e.target.value
                                        )
                                      }
                                      placeholder="Resource title"
                                    />
                                    <Input
                                      value={resource.url}
                                      onChange={(e) =>
                                        handleResourceChange(
                                          sIdx,
                                          rIdx,
                                          "url",
                                          e.target.value
                                        )
                                      }
                                      placeholder="Resource URL"
                                    />
                                  </div>

                                  {resource.type === "quiz" && (
                                    <Textarea
                                      value={resource.content}
                                      onChange={(e) =>
                                        handleResourceChange(
                                          sIdx,
                                          rIdx,
                                          "content",
                                          e.target.value
                                        )
                                      }
                                      placeholder="Quiz instructions or content"
                                    />
                                  )}
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </TabsContent>

              {/* Requirements Tab */}
              <TabsContent value="requirements" className="space-y-6">
                <div className="space-y-6">
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold">
                        Course Requirements
                      </h3>
                      <Button
                        type="button"
                        onClick={addRequirement}
                        variant="outline"
                        size="sm"
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        Add Requirement
                      </Button>
                    </div>
                    <div className="space-y-3">
                      {requirements.map((req, index) => (
                        <div key={index} className="flex gap-2">
                          <Input
                            value={req}
                            onChange={(e) =>
                              updateRequirement(index, e.target.value)
                            }
                            placeholder="Basic knowledge of..."
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => removeRequirement(index)}
                            disabled={requirements.length === 1}
                            className="text-red-600"
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>

                  <Separator />

                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold">
                        What You'll Learn
                      </h3>
                      <Button
                        type="button"
                        onClick={addLearningOutcome}
                        variant="outline"
                        size="sm"
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        Add Outcome
                      </Button>
                    </div>
                    <div className="space-y-3">
                      {whatYouWillLearn.map((outcome, index) => (
                        <div key={index} className="flex gap-2">
                          <Input
                            value={outcome}
                            onChange={(e) =>
                              updateLearningOutcome(index, e.target.value)
                            }
                            placeholder="How to build..."
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => removeLearningOutcome(index)}
                            disabled={whatYouWillLearn.length === 1}
                            className="text-red-600"
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </TabsContent>

              {/* Settings Tab */}
              <TabsContent value="settings" className="space-y-6">
                <div className="space-y-6">
                  <Card>
                    <CardHeader>
                      <CardTitle>Publication Settings</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <Label htmlFor="published">Publish Course</Label>
                          <p className="text-sm text-gray-500">
                            Make this course visible to students
                          </p>
                        </div>
                        <Switch
                          id="published"
                          checked={isPublished}
                          onCheckedChange={setIsPublished}
                        />
                      </div>

                      <Separator />

                      <div className="flex items-center justify-between">
                        <div>
                          <Label htmlFor="certificate">
                            Enable Certificates
                          </Label>
                          <p className="text-sm text-gray-500">
                            Award certificates upon course completion
                          </p>
                        </div>
                        <Switch
                          id="certificate"
                          checked={certificateEnabled}
                          onCheckedChange={setCertificateEnabled}
                        />
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>Course Statistics</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                        <div className="p-4 bg-blue-50 rounded-lg">
                          <div className="text-2xl font-bold text-blue-600">
                            {sections.length}
                          </div>
                          <div className="text-sm text-blue-600">Sections</div>
                        </div>
                        <div className="p-4 bg-green-50 rounded-lg">
                          <div className="text-2xl font-bold text-green-600">
                            {sections.reduce(
                              (total, section) =>
                                total + section.lessons.length,
                              0
                            )}
                          </div>
                          <div className="text-sm text-green-600">Lessons</div>
                        </div>
                        <div className="p-4 bg-purple-50 rounded-lg">
                          <div className="text-2xl font-bold text-purple-600">
                            {sections.reduce(
                              (total, section) =>
                                total + section.resources.length,
                              0
                            )}
                          </div>
                          <div className="text-sm text-purple-600">
                            Resources
                          </div>
                        </div>
                        <div className="p-4 bg-orange-50 rounded-lg">
                          <div className="text-2xl font-bold text-orange-600">
                            {sections.reduce(
                              (total, section) =>
                                total +
                                section.lessons.reduce(
                                  (lessonTotal, lesson) =>
                                    lessonTotal +
                                    (lesson.duration
                                      ? parseInt(lesson.duration) || 0
                                      : 0),
                                  0
                                ),
                              0
                            )}
                          </div>
                          <div className="text-sm text-orange-600">Minutes</div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>Preview Settings</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="bg-gray-50 p-4 rounded-lg">
                        <h4 className="font-medium mb-2">
                          Free Preview Lessons
                        </h4>
                        <div className="text-sm text-gray-600 space-y-1">
                          {sections.map((section, sIdx) =>
                            section.lessons
                              .filter((lesson) => lesson.isFree)
                              .map((lesson, lIdx) => (
                                <div
                                  key={`${sIdx}-${lIdx}`}
                                  className="flex items-center gap-2"
                                >
                                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                                  <span>
                                    {section.title} -{" "}
                                    {lesson.title || `Lesson ${lIdx + 1}`}
                                  </span>
                                </div>
                              ))
                          )}
                          {sections.every((section) =>
                            section.lessons.every((lesson) => !lesson.isFree)
                          ) && (
                            <p className="text-gray-500 italic">
                              No free preview lessons selected
                            </p>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>

            {/* Form Actions */}
            <div className="sticky bottom-0 bg-white border-t pt-6 mt-8">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <Badge variant={isPublished ? "default" : "secondary"}>
                    {isPublished ? "Will be published" : "Draft"}
                  </Badge>
                  <Badge variant={isFree ? "secondary" : "default"}>
                    {isFree
                      ? "Free Course"
                      : `${price}${
                          discountPrice ? ` (was ${discountPrice})` : ""
                        }`}
                  </Badge>
                </div>

                <div className="flex gap-3">
                  <Button type="button" variant="outline">
                    Save as Draft
                  </Button>
                  <Button
                    type="submit"
                    className="bg-blue-600 hover:bg-blue-700 text-white"
                    disabled={
                      !title ||
                      !slug ||
                      !description ||
                      !category ||
                      (!isFree && !price)
                    }
                  >
                    {isPublished ? "Create & Publish Course" : "Create Course"}
                  </Button>
                </div>
              </div>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
