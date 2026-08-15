import { useState } from "react"
import { UserCog, AlertTriangle, RefreshCw } from "lucide-react"
import { Badge } from "@/components/ui/badge"
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
import { useRoles } from "@/features/roles/useRoles"
import { RoleDetailSheet } from "@/features/roles/RoleDetailSheet"
import { cn } from "@/lib/utils"
import type { RoleWithPermissionsResponse } from "@/types/rbac"

// REAL API DATA: every row comes from GET /v1/roles (roles:read-gated) —
// these are the platform-seeded roles that actually exist in the
// database (see migrations 000021/000023), never invented ones.
export function RolesPage() {
  const { data, isLoading, isError, refetch, isRefetching } = useRoles()
  const [selectedRole, setSelectedRole] = useState<RoleWithPermissionsResponse | null>(null)

  const roles = data?.data ?? []

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-3">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
          <UserCog className="size-5" strokeWidth={1.75} aria-hidden="true" />
        </span>
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Roles</h1>
          <p className="text-sm text-muted-foreground">
            Permissions are granted through roles — assign a role to a user rather than editing
            permissions individually.
          </p>
        </div>
      </div>

      {!isLoading && isError && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-12 text-center">
          <AlertTriangle className="size-5 text-muted-foreground" strokeWidth={1.5} aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-foreground">Unable to load roles</p>
            <p className="mt-1 text-sm text-muted-foreground">
              You may not have permission to view roles, or something went wrong.
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
                <TableHead>Role</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Users</TableHead>
                <TableHead>Permissions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {roles.map((role) => (
                <TableRow key={role.id} className="cursor-pointer" onClick={() => setSelectedRole(role)}>
                  <TableCell className="font-medium">{role.name}</TableCell>
                  <TableCell className="max-w-xs truncate text-muted-foreground">
                    {role.description ?? "—"}
                  </TableCell>
                  <TableCell>{role.user_count}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {role.permissions.slice(0, 3).map((p) => (
                        <Badge key={p.id} variant="outline" className="font-mono text-xs">
                          {p.name}
                        </Badge>
                      ))}
                      {role.permissions.length > 3 && (
                        <Badge variant="outline" className="text-xs">
                          +{role.permissions.length - 3}
                        </Badge>
                      )}
                      {role.permissions.length === 0 && (
                        <span className="text-xs text-muted-foreground">None</span>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <RoleDetailSheet role={selectedRole} onOpenChange={(open) => !open && setSelectedRole(null)} />
    </div>
  )
}
