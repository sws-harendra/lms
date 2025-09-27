"use client";
import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { fetchUserById } from "@/lib/store/features/adminSlice";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";
import { adminServices } from "@/services/admin/admin.service";

const UserDetailPage = () => {
  const params = useParams();
  const id = params?.id;
  const dispatch = useDispatch();
  const router = useRouter();
  const { userDetail, userDetailStatus, userDetailError } = useSelector(
    (s) => s.admin
  );

  useEffect(() => {
    if (id) dispatch(fetchUserById(id));
  }, [dispatch, id]);

  const handleDelete = async () => {
    if (!id) return;
    const ok = window.confirm("Delete this user? This action cannot be undone.");
    if (!ok) return;
    try {
      await adminServices.deleteUser(id);
      router.push("/admin/(mainapp)/dashboard/users");
    } catch (e) {
      alert(e?.response?.data?.message || "Failed to delete user");
    }
  };

  if (userDetailStatus === "loading")
    return <div className="p-4">Loading user...</div>;
  if (userDetailStatus === "failed")
    return (
      <div className="p-4 text-red-600">
        {userDetailError || "Failed to load user"}
      </div>
    );

  if (!userDetail) return null;

  return (
    <div className="p-4 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Avatar className="h-16 w-16">
            <AvatarImage src={getMediaUrl(userDetail.profileImage) || ""} />
            <AvatarFallback>
              {userDetail.name
                ?.split(" ")
                ?.map((n) => n[0])
                .join("") || "U"}
            </AvatarFallback>
          </Avatar>
          <div>
            <h1 className="text-2xl font-semibold">{userDetail.name}</h1>
            <div className="text-muted-foreground">{userDetail.email}</div>
            <div className="mt-2 flex items-center gap-2">
              <Badge variant="secondary">{userDetail.role?.name || "-"}</Badge>
              {userDetail.isVerified ? (
                <Badge className="bg-green-600 hover:bg-green-600">
                  Verified
                </Badge>
              ) : (
                <Badge className="bg-gray-400 hover:bg-gray-400">Pending</Badge>
              )}
            </div>
          </div>
        </div>
        <div className="space-x-2">
          <Button asChild variant="outline">
            <Link href="/admin/(mainapp)/dashboard/users">Back</Link>
          </Button>
          <Button asChild variant="secondary">
            <Link href={`/admin/(mainapp)/dashboard/users/${id}/edit`}>Edit</Link>
          </Button>
          <Button variant="destructive" onClick={handleDelete}>Delete</Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="space-y-2">
          <h2 className="text-lg font-semibold">Profile</h2>
          <div className="rounded border p-4 space-y-2">
            <div>
              <span className="font-medium">Phone:</span>{" "}
              {userDetail.phone || "-"}
            </div>
            <div>
              <span className="font-medium">Designation:</span>{" "}
              {userDetail.designation || "-"}
            </div>
            <div>
              <span className="font-medium">Experience:</span>{" "}
              {userDetail.experience ?? "-"} years
            </div>
            <div>
              <span className="font-medium">Skills:</span>{" "}
              {Array.isArray(userDetail.skills) && userDetail.skills.length > 0
                ? userDetail.skills.map((s) => s.name).join(", ")
                : "-"}
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <h2 className="text-lg font-semibold">Location</h2>
          <div className="rounded border p-4 space-y-2">
            <div>
              <span className="font-medium">Country:</span>{" "}
              {userDetail.location?.country || "-"}
            </div>
            <div>
              <span className="font-medium">State:</span>{" "}
              {userDetail.location?.state || "-"}
            </div>
            <div>
              <span className="font-medium">City:</span>{" "}
              {userDetail.location?.city || "-"}
            </div>
            <div>
              <span className="font-medium">Address:</span>{" "}
              {userDetail.location?.address || "-"}
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <h2 className="text-lg font-semibold">Social</h2>
        <div className="rounded border p-4 space-y-2">
          <div>
            <span className="font-medium">Facebook:</span>{" "}
            {userDetail.social?.facebook || "-"}
          </div>
          <div>
            <span className="font-medium">LinkedIn:</span>{" "}
            {userDetail.social?.linkedin || "-"}
          </div>
          <div>
            <span className="font-medium">Twitter:</span>{" "}
            {userDetail.social?.twitter || "-"}
          </div>
          <div>
            <span className="font-medium">Instagram:</span>{" "}
            {userDetail.social?.instagram || "-"}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UserDetailPage;
