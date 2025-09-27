"use client";
import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useDispatch, useSelector } from "react-redux";
import {
  fetchAllUsers,
  setUserFilters,
  setUserPagination,
} from "@/lib/store/features/adminSlice";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getMediaUrl } from "@/app/utils/getAssetsUrl";
import { adminServices } from "@/services/admin/admin.service";

const AllUsers = () => {
  const dispatch = useDispatch();
  const router = useRouter();
  const { users, usersStatus, usersError, pagination, summary, filters } =
    useSelector((s) => s.admin);

  const [localSearch, setLocalSearch] = useState(filters.search || "");

  // fetch whenever filters/pagination change
  useEffect(() => {
    dispatch(
      fetchAllUsers({
        page: pagination.page,
        limit: pagination.limit,
        search: filters.search,
        role: filters.role,
      })
    );
  }, [
    dispatch,
    pagination.page,
    pagination.limit,
    filters.search,
    filters.role,
  ]);

  const totalPages = useMemo(
    () => pagination.totalPages || 0,
    [pagination.totalPages]
  );

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    dispatch(setUserFilters({ search: localSearch }));
    dispatch(setUserPagination({ page: 1 }));
  };

  const handleRoleChange = (value) => {
    dispatch(setUserFilters({ role: value === "all" ? "" : value }));
    dispatch(setUserPagination({ page: 1 }));
  };

  const goToPage = (page) => {
    if (page < 1 || page > totalPages) return;
    dispatch(setUserPagination({ page }));
  };

  const handleDelete = async (id) => {
    const ok = window.confirm(
      "Delete this user? This action cannot be undone."
    );
    if (!ok) return;
    try {
      await adminServices.deleteUser(id);
      // refetch same page with current filters
      dispatch(
        fetchAllUsers({
          page: pagination.page,
          limit: pagination.limit,
          search: filters.search,
          role: filters.role,
        })
      );
    } catch (e) {
      alert(e?.response?.data?.message || "Failed to delete user");
    }
  };

  return (
    <div className="p-4">
      <div className="flex items-center justify-between mb-4 gap-4">
        <h1 className="text-2xl font-semibold">Users</h1>
        <div className="flex-1" />
        <form
          onSubmit={handleSearchSubmit}
          className="flex items-center gap-2 max-w-md w-full"
        >
          <Input
            placeholder="Search by name or email..."
            value={localSearch}
            onChange={(e) => setLocalSearch(e.target.value)}
          />
          <Select
            onValueChange={handleRoleChange}
            value={filters.role || "all"}
          >
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Filter role" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All roles</SelectItem>
              <SelectItem value="admin">Admin</SelectItem>
              <SelectItem value="instructor">Instructor</SelectItem>
              <SelectItem value="user">User</SelectItem>
            </SelectContent>
          </Select>
          <Button type="submit">Search</Button>
        </form>
        <Button asChild>
          <Link href="/admin/(mainapp)/dashboard/users/add-user">Add User</Link>
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <Card>
          <CardHeader>
            <CardTitle>Total</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {summary.totalUsers || 0}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Admins</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {summary.byRole?.admin || 0}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Instructors</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {summary.byRole?.instructor || 0}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Users</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-bold">
            {summary.byRole?.user || 0}
          </CardContent>
        </Card>
      </div>

      {usersStatus === "loading" && <div>Loading users...</div>}
      {usersStatus === "failed" && (
        <div className="text-red-600">
          {usersError || "Failed to load users"}
        </div>
      )}

      {usersStatus === "succeeded" && (
        <Table>
          <TableCaption>List of all users and their roles.</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>User</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Verified</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.map((u) => (
              <TableRow key={u._id}>
                <TableCell>
                  <div className="flex items-center gap-3">
                    <Avatar>
                      <AvatarImage src={getMediaUrl(u.profileImage) || ""} />
                      <AvatarFallback>
                        {u.name
                          ?.split(" ")
                          ?.map((n) => n[0])
                          .join("") || "U"}
                      </AvatarFallback>
                    </Avatar>
                    <div>
                      <div className="font-medium">{u.name}</div>
                    </div>
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {u.email}
                </TableCell>
                <TableCell>
                  <Badge variant="secondary">{u.role?.name || "-"}</Badge>
                </TableCell>
                <TableCell>
                  {u.isVerified ? (
                    <Badge className="bg-green-600 hover:bg-green-600">
                      Verified
                    </Badge>
                  ) : (
                    <Badge className="bg-gray-400 hover:bg-gray-400">
                      Pending
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="text-right space-x-2">
                  <Button variant="outline" asChild>
                    <Link href={`/admin/(mainapp)/dashboard/users/${u._id}`}>
                      View
                    </Link>
                  </Button>
                  {/* <Button variant="secondary" asChild>
                    <Link
                      href={`/admin/(mainapp)/dashboard/users/${u._id}/edit`}
                    >
                      Edit
                    </Link>
                  </Button> */}
                  <Button
                    variant="destructive"
                    onClick={() => handleDelete(u._id)}
                  >
                    Delete
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {/* Pagination Controls */}
      {usersStatus === "succeeded" && totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <div className="text-sm text-muted-foreground">
            Page {pagination.page} of {totalPages}
          </div>
          <div className="space-x-2">
            <Button
              variant="outline"
              onClick={() => goToPage(pagination.page - 1)}
              disabled={pagination.page <= 1}
            >
              Prev
            </Button>
            <Button
              variant="outline"
              onClick={() => goToPage(pagination.page + 1)}
              disabled={pagination.page >= totalPages}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};

export default AllUsers;
