import { useState } from "react"
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet"
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
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useSecretPolicy, useSecretPolicyAssignments } from "@/features/secretPolicies/useSecretPolicy"
import { useAssignSecretPolicy, useUnassignSecretPolicy } from "@/features/secretPolicies/useSecretPolicyAssignment"
import { useDeleteSecretPolicy } from "@/features/secretPolicies/useDeleteSecretPolicy"
import { useRoles } from "@/features/roles/useRoles"
import { usePermission } from "@/features/auth/usePermission"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { Trash2, X } from "lucide-react"
import { toast } from "sonner"

export function PolicyDetailSheet({
  policyId,
  onOpenChange,
}: {
  policyId: string | null
  onOpenChange: (open: boolean) => void
}) {
  const { data: detail, isLoading } = useSecretPolicy(policyId)
  const { data: assignments } = useSecretPolicyAssignments(policyId)
  const { data: rolesResponse } = useRoles()
  const canAssign = usePermission("secret_policies:assign")
  const canDelete = usePermission("secret_policies:delete")

  const assign = useAssignSecretPolicy(policyId ?? "")
  const unassign = useUnassignSecretPolicy(policyId ?? "")
  const deletePolicy = useDeleteSecretPolicy()

  const [roleToAssign, setRoleToAssign] = useState("")
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  const roles = rolesResponse?.data ?? []
  const roleName = (roleId: string) => roles.find((r) => r.id === roleId)?.name ?? roleId
  const assignedRoleIds = new Set(assignments?.data ?? [])
  const assignableRoles = roles.filter((r) => !assignedRoleIds.has(r.id))

  function handleAssign() {
    if (!roleToAssign) return
    assign.mutate(roleToAssign, {
      onSuccess: () => {
        toast.success(`Policy assigned to ${roleName(roleToAssign)}.`)
        setRoleToAssign("")
      },
      onError: (error) => toast.error(friendlyErrorMessage(error)),
    })
  }

  function handleUnassign(roleId: string) {
    unassign.mutate(roleId, {
      onSuccess: () => toast.success(`Policy unassigned from ${roleName(roleId)}.`),
      onError: (error) => toast.error(friendlyErrorMessage(error)),
    })
  }

  function handleDelete() {
    if (!policyId) return
    deletePolicy.mutate(policyId, {
      onSuccess: () => {
        toast.success("Policy deleted.")
        setConfirmingDelete(false)
        onOpenChange(false)
      },
      onError: (error) => {
        toast.error(friendlyErrorMessage(error))
        setConfirmingDelete(false)
      },
    })
  }

  return (
    <Sheet open={policyId !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{detail?.name}</SheetTitle>
          <SheetDescription>{detail?.description ?? "No description."}</SheetDescription>
        </SheetHeader>

        {isLoading && (
          <div className="flex flex-col gap-2 px-4">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-6 w-full" />
          </div>
        )}

        {detail && (
          <div className="flex flex-col gap-6 overflow-y-auto px-4 pb-6">
            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">Rules</h3>
              {detail.rules.length === 0 && (
                <p className="text-sm text-muted-foreground">No rules — this policy grants nothing.</p>
              )}
              <ul className="flex flex-col gap-2">
                {detail.rules.map((rule) => (
                  <li key={rule.id} className="rounded-lg border p-2">
                    <div className="flex items-center justify-between gap-2">
                      <code className="text-xs font-medium">{rule.path_pattern}</code>
                      <Badge variant={rule.effect === "deny" ? "destructive" : "outline"} className="text-xs">
                        {rule.effect}
                      </Badge>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {rule.actions.map((action) => (
                        <Badge key={action} variant="secondary" className="text-xs">
                          {action}
                        </Badge>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            </section>

            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">Assigned roles</h3>
              {assignedRoleIds.size === 0 && (
                <p className="text-sm text-muted-foreground">Not assigned to any role.</p>
              )}
              <ul className="flex flex-col gap-1.5">
                {[...assignedRoleIds].map((roleId) => (
                  <li key={roleId} className="flex items-center justify-between text-sm">
                    <span>{roleName(roleId)}</span>
                    {canAssign && (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`Unassign from ${roleName(roleId)}`}
                        onClick={() => handleUnassign(roleId)}
                        disabled={unassign.isPending}
                      >
                        <X />
                      </Button>
                    )}
                  </li>
                ))}
              </ul>

              {canAssign && (
                <div className="flex items-center gap-2 pt-1">
                  <Select value={roleToAssign} onValueChange={setRoleToAssign}>
                    <SelectTrigger className="flex-1">
                      <SelectValue placeholder="Assign to a role…" />
                    </SelectTrigger>
                    <SelectContent>
                      {assignableRoles.map((role) => (
                        <SelectItem key={role.id} value={role.id}>
                          {role.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button size="sm" onClick={handleAssign} disabled={!roleToAssign || assign.isPending}>
                    Assign
                  </Button>
                </div>
              )}
            </section>

            {canDelete && (
              <Button variant="destructive" size="sm" onClick={() => setConfirmingDelete(true)}>
                <Trash2 />
                Delete policy
              </Button>
            )}
          </div>
        )}
      </SheetContent>

      <AlertDialog open={confirmingDelete} onOpenChange={setConfirmingDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete policy "{detail?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              Every role currently assigned this policy immediately loses whatever path access it
              granted. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={handleDelete}
              disabled={deletePolicy.isPending}
            >
              {deletePolicy.isPending ? "Deleting…" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Sheet>
  )
}
