"use client";
import { courseService } from "@/services/course.service";
import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

const AllCategories = () => {
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", slug: "", description: "" });
  const [slugEdited, setSlugEdited] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState({ id: null, name: "", slug: "", description: "" });
  const [editSlugEdited, setEditSlugEdited] = useState(false);
  const [editSubmitting, setEditSubmitting] = useState(false);

  useEffect(() => {
    const fetchCategories = async () => {
      try {
        setLoading(true);
        const data = await courseService.getAllCategories();
        setCategories(data?.categories || data); // adjust depending on API response
      } catch (err) {
        setError("Failed to load categories");
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchCategories();
  }, []);

  const reloadCategories = async () => {
    try {
      setLoading(true);
      const data = await courseService.getAllCategories();
      setCategories(data?.categories || data);
    } catch (err) {
      setError("Failed to load categories");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const startEdit = (cat) => {
    setError(null);
    setEditForm({ id: cat._id || cat.id, name: cat.name || "", slug: cat.slug || "", description: cat.description || "" });
    setEditSlugEdited(false);
    setEditOpen(true);
  };

  const onEditChange = (e) => {
    const { name, value } = e.target;
    setEditForm((prev) => {
      const next = { ...prev, [name]: value };
      if (name === "name" && !editSlugEdited) {
        next.slug = slugify(value || "");
      }
      if (name === "slug") {
        setEditSlugEdited(true);
        next.slug = slugify(value || "");
      }
      return next;
    });
  };

  const onEditSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (!editForm.name?.trim()) {
      setError("Name is required");
      return;
    }
    try {
      setEditSubmitting(true);
      await courseService.updateCategory(editForm.id, {
        name: editForm.name.trim(),
        slug: (editForm.slug?.trim() || slugify(editForm.name.trim())),
        description: editForm.description?.trim() || "",
      });
      setEditOpen(false);
      setEditForm({ id: null, name: "", slug: "", description: "" });
      setEditSlugEdited(false);
      await reloadCategories();
    } catch (err) {
      console.error(err);
      const msg = err?.response?.data?.message || "Failed to update category";
      setError(msg);
    } finally {
      setEditSubmitting(false);
    }
  };

  const onConfirmDelete = async (id) => {
    setError(null);
    try {
      await courseService.deleteCategory(id);
      await reloadCategories();
    } catch (err) {
      console.error(err);
      const msg = err?.response?.data?.message || "Failed to delete category";
      setError(msg);
    }
  };

  const slugify = (str) =>
    str
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");

  const onChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => {
      const next = { ...prev, [name]: value };
      if (name === "name" && !slugEdited) {
        next.slug = slugify(value || "");
      }
      if (name === "slug") {
        setSlugEdited(true);
        next.slug = slugify(value || "");
      }
      return next;
    });
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (!form.name?.trim()) {
      setError("Name is required");
      return;
    }
    const payload = {
      name: form.name.trim(),
      slug: (form.slug?.trim() || slugify(form.name.trim())),
      description: form.description?.trim() || "",
    };
    try {
      setSubmitting(true);
      await courseService.createCategory(payload);
      setOpen(false);
      setForm({ name: "", slug: "", description: "" });
      setSlugEdited(false);
      await reloadCategories();
    } catch (err) {
      console.error(err);
      const msg = err?.response?.data?.message || "Failed to create category";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) return <p>Loading categories...</p>;
  if (error) return (
    <div className="space-y-2">
      <p className="text-red-600 text-sm">{error}</p>
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Categories</h2>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm">Add Category</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Category</DialogTitle>
              <DialogDescription>
                Create a new category using only a name and description.
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={onSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  name="name"
                  placeholder="e.g. Web Development"
                  value={form.name}
                  onChange={onChange}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="slug">Slug</Label>
                <Input
                  id="slug"
                  name="slug"
                  placeholder="auto-generated from name"
                  value={form.slug}
                  onChange={onChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  name="description"
                  placeholder="Short description (optional)"
                  value={form.description}
                  onChange={onChange}
                  rows={3}
                />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={submitting}>
                  {submitting ? "Saving..." : "Save"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
        {/* Edit Category Dialog */}
        <Dialog open={editOpen} onOpenChange={setEditOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Edit Category</DialogTitle>
              <DialogDescription>Update the category details.</DialogDescription>
            </DialogHeader>
            <form onSubmit={onEditSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="edit-name">Name</Label>
                <Input
                  id="edit-name"
                  name="name"
                  value={editForm.name}
                  onChange={onEditChange}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-slug">Slug</Label>
                <Input
                  id="edit-slug"
                  name="slug"
                  value={editForm.slug}
                  onChange={onEditChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-description">Description</Label>
                <Textarea
                  id="edit-description"
                  name="description"
                  value={editForm.description}
                  onChange={onEditChange}
                  rows={3}
                />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setEditOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={editSubmitting}>
                  {editSubmitting ? "Saving..." : "Save"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Slug</TableHead>
            <TableHead className="w-[50%]">Description</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {categories.length > 0 ? (
            categories.map((cat) => (
              <TableRow key={cat._id || cat.id}>
                <TableCell className="font-medium">{cat.name}</TableCell>
                <TableCell>{cat.slug}</TableCell>
                <TableCell className="text-muted-foreground">
                  {cat.description || "—"}
                </TableCell>
                <TableCell className="text-right space-x-2">
                  <Button size="sm" variant="outline" onClick={() => startEdit(cat)}>
                    Edit
                  </Button>
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button size="sm" variant="destructive">Delete</Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Delete category?</AlertDialogTitle>
                        <AlertDialogDescription>
                          This action cannot be undone. If any courses are linked to this category, deletion will be blocked.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction onClick={() => onConfirmDelete(cat._id || cat.id)}>
                          Delete
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </TableCell>
              </TableRow>
            ))
          ) : (
            <TableRow>
              <TableCell colSpan={3} className="text-center py-8">
                No categories found.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
        <TableCaption>Manage course categories</TableCaption>
      </Table>
    </div>
  );
};

export default AllCategories;
