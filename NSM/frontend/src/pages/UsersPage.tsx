import { useMemo, useState } from "react"
import { Users as UsersIcon, Search, AlertTriangle, RefreshCw } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { StatusBadge } from "@/components/StatusBadge"
import { useUsers } from "@/features/users/useUsers"
import { CreateUserDialog } from "@/features/users/CreateUserDialog"
import { UserDetailSheet } from "@/features/users/UserDetailSheet"
import { USER_STATUS_META } from "@/features/users/userDisplay"
import { cn } from "@/lib/utils"

// REAL API DATA: every row comes straight from GET /v1/users
// (users:read-gated by the real backend) — nothing on this page is
// invented or estimated. Role is not shown per-row here: a user's role
// grants are a detail-view concept (a user can hold more than one), so
// the table shows what a list genuinely can — name, email, status — and
// the detail sheet is where roles actually live.
export function UsersPage() {
  const { data, isLoading, isError, refetch, isRefetching } = useUsers()
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
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
            <UsersIcon className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
            <p className="text-sm text-muted-foreground">
              Manage administrator and team accounts for this organization.
            </p>
          </div>
        </div>
        <CreateUserDialog />
      </div>

      <div className="relative max-w-sm">
        <Search
          className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden="true"
        />
        <Input
          placeholder="Search users…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          className="pl-8"
          aria-label="Search users"
        />
      </div>

      {!isLoading && isError && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-12 text-center">
          <AlertTriangle className="size-5 text-muted-foreground" strokeWidth={1.5} aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-foreground">Unable to load users</p>
            <p className="mt-1 text-sm text-muted-foreground">
              You may not have permission to view users, or something went wrong.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isRefetching}>
            <RefreshCw className={cn("size-3.5", isRefetching && "animate-spin")} />
            {isRefetching ? "Retrying…" : "Retry"}
          </Button>
        </div>
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
                    <StatusBadge
                      icon={USER_STATUS_META[user.status].icon}
                      label={USER_STATUS_META[user.status].label}
                      className={USER_STATUS_META[user.status].className}
                    />
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
