import { useMemo, useState } from "react"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useUsers } from "@/features/users/useUsers"
import { CreateUserDialog } from "@/features/users/CreateUserDialog"
import { UserDetailSheet } from "@/features/users/UserDetailSheet"

// REAL API DATA: every row comes straight from GET /v1/users
// (users:read-gated by the real backend) — nothing on this page is
// invented or estimated. Role is not shown per-row here: a user's role
// grants are a detail-view concept (a user can hold more than one), so
// the table shows what a list genuinely can — name, email, status — and
// the detail sheet is where roles actually live.
export function UsersPage() {
  const { data, isLoading, isError } = useUsers()
  const [search, setSearch] = useState("")
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)

  const filtered = useMemo(() => {
    const users = data?.data ?? []
    const q = search.trim().toLowerCase()
    if (!q) return users
    return users.filter(
      (u) => u.email.toLowerCase().includes(q) || (u.username ?? "").toLowerCase().includes(q),
    )
  }, [data, search])

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
          <p className="text-sm text-muted-foreground">
            Manage administrator and team accounts for this organization.
          </p>
        </div>
        <CreateUserDialog />
      </div>

      <Input
        placeholder="Search users…"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        className="max-w-sm"
        aria-label="Search users"
      />

      {isError && (
        <p className="text-sm text-muted-foreground">
          You don't have permission to view users, or something went wrong.
        </p>
      )}

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}

      {!isLoading && !isError && (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-sm text-muted-foreground">
                    No users found.
                  </TableCell>
                </TableRow>
              )}
              {filtered.map((user) => (
                <TableRow
                  key={user.id}
                  className="cursor-pointer"
                  onClick={() => setSelectedUserId(user.id)}
                >
                  <TableCell className="font-medium">{user.username ?? "—"}</TableCell>
                  <TableCell className="text-muted-foreground">{user.email}</TableCell>
                  <TableCell>
                    <Badge variant={user.status === "active" ? "default" : "outline"} className="capitalize">
                      {user.status.replace("_", " ")}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {new Date(user.created_at).toLocaleDateString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <UserDetailSheet userId={selectedUserId} onOpenChange={(open) => !open && setSelectedUserId(null)} />
    </div>
  )
}
