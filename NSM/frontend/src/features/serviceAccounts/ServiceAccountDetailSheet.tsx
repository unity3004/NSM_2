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
import { useServiceAccount, useServiceAccountCredentials } from "@/features/serviceAccounts/useServiceAccount"
import {
  useAssignServiceAccountRole,
  useDeleteServiceAccount,
  useRemoveServiceAccountRole,
  useRevokeCredential,
  useRotateCredential,
  useUpdateServiceAccount,
} from "@/features/serviceAccounts/useServiceAccountMutations"
import { CreateCredentialDialog } from "@/features/serviceAccounts/CreateCredentialDialog"
import { useRoles } from "@/features/roles/useRoles"
import { usePermission } from "@/features/auth/usePermission"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { Check, Copy, KeyRound, Power, RotateCw, Trash2, TriangleAlert, X } from "lucide-react"
import { toast } from "sonner"

function formatDate(value?: string | null): string {
  if (!value) return "Never"
  return new Date(value).toLocaleString()
}

export function ServiceAccountDetailSheet({
  serviceAccountId,
  onOpenChange,
}: {
  serviceAccountId: string | null
  onOpenChange: (open: boolean) => void
}) {
  const { data: detail, isLoading } = useServiceAccount(serviceAccountId)
  const { data: credentials } = useServiceAccountCredentials(serviceAccountId)
  const { data: rolesResponse } = useRoles()

  const canDisable = usePermission("service_accounts:disable")
  const canDelete = usePermission("service_accounts:delete")
  const canAssignRole = usePermission("roles:update")
  const canCreateCredential = usePermission("api_keys:create")
  const canRevokeCredential = usePermission("api_keys:delete")
  const canRotateCredential = usePermission("api_keys:rotate")

  const id = serviceAccountId ?? ""
  const updateServiceAccount = useUpdateServiceAccount(id)
  const assignRole = useAssignServiceAccountRole(id)
  const removeRole = useRemoveServiceAccountRole(id)
  const deleteServiceAccount = useDeleteServiceAccount()
  const revokeCredential = useRevokeCredential(id)
  const rotateCredential = useRotateCredential(id)

  const [roleToAssign, setRoleToAssign] = useState("")
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [creatingCredential, setCreatingCredential] = useState(false)
  // rotatedSecret holds the one and only response that ever carries a
  // rotated credential's raw secret — shown inline, once, the same
  // "never retrievable again" guarantee CreateCredentialDialog's own doc
  // comment makes for a freshly-issued credential.
  const [rotatedSecret, setRotatedSecret] = useState<{ name: string; secret: string } | null>(null)
  const [secretCopied, setSecretCopied] = useState(false)

  const roles = rolesResponse?.data ?? []
  const assignedRoleIds = new Set((detail?.roles ?? []).map((r) => r.role_id))
  const assignableRoles = roles.filter((r) => !assignedRoleIds.has(r.id))

  function handleAssignRole() {
    if (!roleToAssign) return
    const role = roles.find((r) => r.id === roleToAssign)
    assignRole.mutate(roleToAssign, {
      onSuccess: () => {
        toast.success(`Granted ${role?.name ?? "role"}.`)
        setRoleToAssign("")
      },
      onError: (error) => toast.error(friendlyErrorMessage(error)),
    })
  }

  function handleRemoveRole(roleId: string, roleName: string) {
    removeRole.mutate(roleId, {
      onSuccess: () => toast.success(`Removed ${roleName}.`),
      onError: (error) => toast.error(friendlyErrorMessage(error)),
    })
  }

  function handleToggleStatus() {
    if (!detail) return
    const next = detail.status === "active" ? "disabled" : "active"
    updateServiceAccount.mutate(
      { name: detail.name, description: detail.description ?? undefined, status: next },
      {
        onSuccess: () => {
          toast.success(
            next === "disabled"
              ? "Service account disabled — its active credentials were revoked."
              : "Service account re-enabled.",
          )
        },
        onError: (error) => toast.error(friendlyErrorMessage(error)),
      },
    )
  }

  function handleDelete() {
    if (!serviceAccountId) return
    deleteServiceAccount.mutate(serviceAccountId, {
      onSuccess: () => {
        toast.success("Service account deleted.")
        setConfirmingDelete(false)
        onOpenChange(false)
      },
      onError: (error) => {
        toast.error(friendlyErrorMessage(error))
        setConfirmingDelete(false)
      },
    })
  }

  function handleRevoke(credentialId: string, name: string) {
    revokeCredential.mutate(credentialId, {
      onSuccess: () => toast.success(`Revoked credential "${name}".`),
      onError: (error) => toast.error(friendlyErrorMessage(error)),
    })
  }

  function handleRotate(credentialId: string, name: string) {
    rotateCredential.mutate(credentialId, {
      onSuccess: (rotated) => {
        toast.success(`Rotated "${name}" — copy the new secret now, it won't be shown again.`)
        setRotatedSecret({ name, secret: rotated.secret })
        setSecretCopied(false)
      },
      onError: (error) => toast.error(friendlyErrorMessage(error)),
    })
  }

  async function handleCopyRotatedSecret(secret: string) {
    try {
      await navigator.clipboard.writeText(secret)
      toast.success("Copied to clipboard.")
      setSecretCopied(true)
    } catch {
      toast.error("Could not copy — your browser may be blocking clipboard access.")
    }
  }

  return (
    <Sheet open={serviceAccountId !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader>
          <div className="flex items-center gap-2">
            <SheetTitle>{detail?.name}</SheetTitle>
            {detail && (
              <Badge variant={detail.status === "active" ? "outline" : "destructive"} className="text-xs">
                {detail.status}
              </Badge>
            )}
          </div>
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
            <section className="grid grid-cols-2 gap-2 text-sm">
              <div>
                <div className="text-muted-foreground">Created</div>
                <div>{formatDate(detail.created_at)}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Last authenticated</div>
                <div>{formatDate(detail.last_authenticated_at)}</div>
              </div>
            </section>

            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">Assigned roles</h3>
              {detail.roles.length === 0 && (
                <p className="text-sm text-muted-foreground">No roles assigned — this identity can authenticate but has no permissions.</p>
              )}
              <ul className="flex flex-col gap-1.5">
                {detail.roles.map((grant) => (
                  <li key={grant.role_id} className="flex items-center justify-between text-sm">
                    <span>{grant.role_name}</span>
                    {canAssignRole && (
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`Remove ${grant.role_name}`}
                        onClick={() => handleRemoveRole(grant.role_id, grant.role_name)}
                        disabled={removeRole.isPending}
                      >
                        <X />
                      </Button>
                    )}
                  </li>
                ))}
              </ul>

              {canAssignRole && (
                <div className="flex items-center gap-2 pt-1">
                  <Select value={roleToAssign} onValueChange={setRoleToAssign}>
                    <SelectTrigger className="flex-1">
                      <SelectValue placeholder="Grant a role…" />
                    </SelectTrigger>
                    <SelectContent>
                      {assignableRoles.map((role) => (
                        <SelectItem key={role.id} value={role.id}>
                          {role.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button size="sm" onClick={handleAssignRole} disabled={!roleToAssign || assignRole.isPending}>
                    Grant
                  </Button>
                </div>
              )}
            </section>

            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">Effective permissions</h3>
              {detail.permissions.length === 0 ? (
                <p className="text-sm text-muted-foreground">None.</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {detail.permissions.map((p) => (
                    <Badge key={p.id} variant="secondary" className="text-xs">
                      {p.name}
                    </Badge>
                  ))}
                </div>
              )}
            </section>

            <section className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium">Credentials</h3>
                {canCreateCredential && (
                  <Button size="sm" variant="outline" onClick={() => setCreatingCredential(true)}>
                    <KeyRound />
                    Issue credential
                  </Button>
                )}
              </div>
              {rotatedSecret && (
                <div className="flex items-start gap-3 rounded-lg border border-destructive/50 bg-destructive/10 p-3">
                  <TriangleAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
                  <div className="flex flex-1 flex-col gap-2">
                    <p className="text-sm font-medium text-destructive">
                      New secret for "{rotatedSecret.name}" — shown once, copy it now.
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 overflow-x-auto rounded-md border bg-muted px-2 py-1.5 text-xs">
                        {rotatedSecret.secret}
                      </code>
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        aria-label="Copy rotated secret to clipboard"
                        onClick={() => void handleCopyRotatedSecret(rotatedSecret.secret)}
                      >
                        {secretCopied ? <Check className="text-green-600" /> : <Copy />}
                      </Button>
                    </div>
                    <Button size="sm" variant="ghost" className="self-start" onClick={() => setRotatedSecret(null)}>
                      Done — I've stored it
                    </Button>
                  </div>
                </div>
              )}
              {(credentials?.data ?? []).length === 0 && (
                <p className="text-sm text-muted-foreground">No credentials yet.</p>
              )}
              <ul className="flex flex-col gap-2">
                {(credentials?.data ?? []).map((key) => (
                  <li key={key.id} className="flex flex-col gap-1 rounded-lg border p-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium">{key.name}</span>
                      <Badge variant={key.status === "active" ? "outline" : "destructive"} className="text-xs">
                        {key.status}
                      </Badge>
                    </div>
                    <code className="text-xs text-muted-foreground">{key.key_prefix}…</code>
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>Last used: {formatDate(key.last_used_at)}</span>
                      {key.status === "active" && (
                        <div className="flex gap-1">
                          {canRotateCredential && (
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              aria-label={`Rotate ${key.name}`}
                              onClick={() => handleRotate(key.id, key.name)}
                              disabled={rotateCredential.isPending}
                            >
                              <RotateCw />
                            </Button>
                          )}
                          {canRevokeCredential && (
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              aria-label={`Revoke ${key.name}`}
                              onClick={() => handleRevoke(key.id, key.name)}
                              disabled={revokeCredential.isPending}
                            >
                              <X />
                            </Button>
                          )}
                        </div>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </section>

            <section className="flex flex-wrap gap-2">
              {canDisable && (
                <Button variant="outline" size="sm" onClick={handleToggleStatus} disabled={updateServiceAccount.isPending}>
                  <Power />
                  {detail.status === "active" ? "Disable" : "Re-enable"}
                </Button>
              )}
              {canDelete && (
                <Button variant="destructive" size="sm" onClick={() => setConfirmingDelete(true)}>
                  <Trash2 />
                  Delete
                </Button>
              )}
            </section>
          </div>
        )}
      </SheetContent>

      {serviceAccountId && (
        <CreateCredentialDialog
          serviceAccountId={serviceAccountId}
          open={creatingCredential}
          onOpenChange={setCreatingCredential}
        />
      )}

      <AlertDialog open={confirmingDelete} onOpenChange={setConfirmingDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete service account "{detail?.name}"?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently removes its role grants and revokes every credential it owns. Any
              access token it already holds remains valid until it expires. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={handleDelete}
              disabled={deleteServiceAccount.isPending}
            >
              {deleteServiceAccount.isPending ? "Deleting…" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Sheet>
  )
}
