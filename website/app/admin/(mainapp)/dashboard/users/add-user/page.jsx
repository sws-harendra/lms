"use client";
import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { adminServices } from "@/services/admin/admin.service";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const AddUsers = () => {
  const router = useRouter();
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    phone: "",
    roleName: "user",
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const onChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    setSuccess("");
    try {
      const payload = {
        name: form.name.trim(),
        email: form.email.trim(),
        password: form.password,
        phone: form.phone.trim() || undefined,
        roleName: form.roleName,
      };
      const res = await adminServices.createUser(payload);
      setSuccess(res?.message || "User created successfully");
      // redirect to list after short delay
      setTimeout(() => router.push("/admin/(mainapp)/dashboard/users"), 800);
    } catch (err) {
      setError(err?.response?.data?.message || "Failed to create user");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-4">
      <Card className="max-w-2xl mx-auto">
        <CardHeader>
          <CardTitle>Add User</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            {error && <div className="text-red-600 text-sm">{error}</div>}
            {success && <div className="text-green-600 text-sm">{success}</div>}

            <div>
              <label className="block mb-1 text-sm font-medium">Full Name</label>
              <Input name="name" value={form.name} onChange={onChange} placeholder="John Doe" required />
            </div>

            <div>
              <label className="block mb-1 text-sm font-medium">Email</label>
              <Input type="email" name="email" value={form.email} onChange={onChange} placeholder="john@example.com" required />
            </div>

            <div>
              <label className="block mb-1 text-sm font-medium">Password</label>
              <Input type="password" name="password" value={form.password} onChange={onChange} placeholder="••••••••" required />
            </div>

            <div>
              <label className="block mb-1 text-sm font-medium">Phone (optional)</label>
              <Input name="phone" value={form.phone} onChange={onChange} placeholder="+1 555 123 4567" />
            </div>

            <div>
              <label className="block mb-1 text-sm font-medium">Role</label>
              <Select value={form.roleName} onValueChange={(v) => setForm((p) => ({ ...p, roleName: v }))}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User (Student)</SelectItem>
                  <SelectItem value="instructor">Instructor</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-2">
              <Button type="submit" disabled={submitting}>
                {submitting ? "Creating..." : "Create User"}
              </Button>
              <Button type="button" variant="outline" onClick={() => router.push("/admin/(mainapp)/dashboard/users")}>Cancel</Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
};

export default AddUsers;
