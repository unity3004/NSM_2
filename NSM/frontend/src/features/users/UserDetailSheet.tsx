import { useState, type ReactNode } from "react"
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useUserDetail } from "@/features/users/useUserDetail"
import { useSetUserStatus } from "@/features/users/useSetUserStatus"
import { useAssignRole, useRemoveRole } from "@/features/users/useRoleAssignment"
import { useRoles } from "@/features/roles/useRoles"
import { X } from "lucide-react"

export function UserDetailSheet({
  userId,
  onOpenChange,
}: {
  userId: string | null
  onOpenChange: (open: boolean) => void
}) {
  const { data: user, isLoading } = useUserDetail(userId ?? undefined)
  const { data: rolesData } = useRoles()
  const setStatus = useSetUserStatus(user?.status === "disabled" ? "enable" : "disable")
  const assignRole = useAssignRole(userId ?? "")
  const removeRole = useRemoveRole(userId ?? "")
  const [confirmingStatusChange, setConfirmingStatusChange] = useState(false)
  const [selectedRoleId, setSelectedRoleId] = useState<string>("")

  const assignedRoleIds = new Set((user?.roles ?? []).map((r) => r.role_id))
  const availableRoles = (rolesData?.data ?? []).filter((r) => !assignedRoleIds.has(r.id))

  return (
    <Sheet open={userId !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{user?.username ?? "User details"}</SheetTitle>
          <SheetDescription>{user?.email}</SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-6 overflow-y-auto px-4 pb-6">
          {isLoading && (
            <div className="flex flex-col gap-3">
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-full" />
            </div>
          )}

          {user && (
            <>
              <section className="flex flex-col gap-2">
                <Row label="Status">
                  <Badge variant={user.status === "active" ? "default" : "outline"} className="capitalize">
                    {user.status.replace("_", " ")}
                  </Badge>
                </Row>
                <Row label="Created">
                  <span className="text-xs">{new Date(user.created_at).toLocaleString()}</span>
                </Row>
                <Row label="Last login">
                  <span className="text-xs">
                    {user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "Never"}
                  </span>
                </Row>
              </section>

              <section className="flex flex-col gap-2">
                <h3 className="text-sm font-medium">Roles</h3>
                {user.roles.length === 0 && (
                  <p className="text-sm text-muted-foreground">No roles assigned.</p>
                )}
                <ul className="flex flex-col gap-1.5">
                  {user.roles.map((grant) => (
                    <li
                      key={grant.role_id}
                      className="flex items-center justify-between rounded-md border px-2.5 py-1.5"
                    >
                      <span className="text-sm">{grant.role_name}</span>
                      <button
                        type="button"
                        onClick={() => removeRole.mutate(grant.role_id)}
                        disabled={removeRole.isPending}
                        className="text-muted-foreground hover:text-destructive"
                        aria-label={`Remove ${grant.role_name} role`}
                      >
                        <X className="size-3.5" />
                      </button>
                    </li>
                  ))}
                </ul>

                {availableRoles.length > 0 && (
                  <div className="mt-1 flex gap-2">
                    <Select value={selectedRoleId} onValueChange={setSelectedRoleId}>
                      <SelectTrigger className="flex-1">
                        <SelectValue placeholder="Assign a role…" />
                      </SelectTrigger>
                      <SelectContent>
                        {availableRoles.map((role) => (
                          <SelectItem key={role.id} value={role.id}>
                            {role.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button
                      size="sm"
                      disabled={!selectedRoleId || assignRole.isPending}
                      onClick={() => {
                        assignRole.mutate(selectedRoleId, { onSuccess: () => setSelectedRoleId("") })
                      }}
                    >
                      Assign
                    </Button>
                  </div>
                )}
              </section>

              <section className="flex flex-col gap-2">
                <h3 className="text-sm font-medium">Permissions</h3>
                <p className="text-xs text-muted-foreground">
                  Derived from roles — permissions cannot be edited directly here.
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {user.permissions.length === 0 && (
                    <p className="text-sm text-muted-foreground">No permissions.</p>
                  )}
                  {user.permissions.map((p) => (
                    <Badge key={p.id} variant="outline" className="font-mono text-xs">
                      {p.name}
                    </Badge>
                  ))}
                </div>
              </section>

              <section className="flex flex-col gap-2 border-t pt-4">
                <Button
                  variant={user.status === "disabled" ? "default" : "destructive"}
                  onClick={() => setConfirmingStatusChange(true)}
                >
                  {user.status === "disabled" ? "Enable user" : "Disable user"}
                </Button>
              </section>
            </>
          )}
        </div>
      </SheetContent>

      <AlertDialog open={confirmingStatusChange} onOpenChange={setConfirmingStatusChange}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {user?.status === "disabled" ? "Enable this user?" : "Disable this user?"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {user?.status === "disabled"
                ? "They will be able to sign in again once enabled."
                : "This immediately revokes every active session for this account, and they will no longer be able to sign in."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (userId) setStatus.mutate(userId)
                setConfirmingStatusChange(false)
              }}
            >
              Confirm
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Sheet>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-muted-foreground">{label}</span>
      {children}
    </div>
  )
}
