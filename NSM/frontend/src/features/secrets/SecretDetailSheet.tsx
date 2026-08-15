import { useEffect, useState, type ReactNode } from "react"
import { Link } from "react-router-dom"
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet"
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
import { useSecrets } from "@/features/secrets/useSecrets"
import { useRevealSecret } from "@/features/secrets/useRevealSecret"
import { useDeleteSecret } from "@/features/secrets/useDeleteSecret"
import { useSecretVersions } from "@/features/secrets/useSecretVersions"
import { useRollbackSecret } from "@/features/secrets/useRollbackSecret"
import { useAuditLogs } from "@/features/audit/useAuditLogs"
import { UpdateSecretDialog } from "@/features/secrets/UpdateSecretDialog"
import { usePermission } from "@/features/auth/usePermission"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { formatRelativeTime, cn } from "@/lib/utils"
import {
  Eye,
  EyeOff,
  Copy,
  Check,
  Lock,
  AlertTriangle,
  History,
  ArrowRight,
  RotateCcw,
  Trash2,
  type LucideIcon,
} from "lucide-react"
import { toast } from "sonner"
import type { AuditResult } from "@/types/audit"

function iconForAuditAction(action: string): LucideIcon {
  if (action.includes("delete")) return Trash2
  if (action.includes("rollback")) return RotateCcw
  return Lock
}

const RESULT_CLASS: Record<AuditResult, string> = {
  success: "text-kanz-success",
  denied: "text-kanz-warning",
  failure: "text-kanz-danger",
}

/**
 * SecretDetailSheet is the only place in this app that ever holds a
 * decrypted secret value in memory — and only after "Reveal secret" is
 * clicked explicitly (see useRevealSecret's own doc comment: enabled:false,
 * fetched only via refetch()). Closing the sheet (userId prop going to
 * null — see SecretsPage's onOpenChange) unmounts this component, which
 * drops useRevealSecret's only observer; combined with that hook's
 * gcTime: 0, the revealed value is evicted from TanStack Query's cache the
 * moment this component goes away, not just visually hidden. The same
 * unmount happens automatically if the session expires while this sheet is
 * open — ProtectedRoute's redirect to /login unmounts the entire
 * authenticated tree, this component included, with no special
 * session-expiry code needed here.
 */
export function SecretDetailSheet({
  path,
  onOpenChange,
}: {
  path: string | null
  onOpenChange: (open: boolean) => void
}) {
  const { data: secretsList } = useSecrets()
  const secret = secretsList?.data.find((s) => s.path === path)

  const [viewingVersion, setViewingVersion] = useState<number | null>(null)
  const [maskedFields, setMaskedFields] = useState<Set<string>>(new Set())
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [updateOpen, setUpdateOpen] = useState(false)
  // The version a rollback confirmation dialog is currently asking about
  // — null means the dialog is closed. Deliberately separate state from
  // viewingVersion: confirming a rollback for a version must not change
  // which version's data the Reveal section below is showing.
  const [confirmingRollbackVersion, setConfirmingRollbackVersion] = useState<number | null>(null)

  // Always the concrete version currently selected in the UI (the version
  // history list defaults to highlighting the current one) — computed
  // before useRevealSecret specifically so that hook is parameterized by
  // the value the user actually sees selected right now, never by
  // viewingVersion directly. viewingVersion alone would be stale the
  // instant handleReveal below calls setViewingVersion and refetch() in
  // the same tick: React state updates don't apply until the next render,
  // so a query hook keyed off viewingVersion would still be bound to last
  // render's value at the moment refetch() actually runs, silently
  // revealing the wrong version's data (or the current version when a
  // historical one was requested).
  const selectedVersion = viewingVersion ?? secret?.version ?? 1
  const reveal = useRevealSecret(path ?? "", selectedVersion)
  const deleteSecret = useDeleteSecret()
  const versionsQuery = useSecretVersions(path)
  const rollback = useRollbackSecret(path ?? "")
  // Real audit events for this exact secret — the same resource_id/path
  // matching the Audit Explorer's own search already relies on
  // (whereClauseForFilter, backend), so this reads real history, not a
  // fabricated activity feed. Guarded the same way useSecretVersions is:
  // never fetches while the sheet is closed.
  const activity = useAuditLogs({ resource_id: path ?? "", limit: 5 }, { enabled: path !== null })

  const canRead = usePermission("secrets:read")
  const canUpdate = usePermission("secrets:update")
  const canDelete = usePermission("secrets:delete")
  const canRollback = usePermission("secrets:rollback")

  // Reset every bit of per-secret state — including whatever was revealed
  // — the moment a different secret (or none) is opened. This is the
  // "leaving the relevant screen" clear the objective asks for, applied at
  // the granularity of "which secret," not just "the whole app."
  useEffect(() => {
    setViewingVersion(null)
    setMaskedFields(new Set())
    setConfirmingDelete(false)
    setUpdateOpen(false)
    setConfirmingRollbackVersion(null)
  }, [path])

  // REAL API DATA: every row comes from GET /v1/secrets/{path}?versions=true
  // (secrets:read-gated) — created_at, created_by, and current all come
  // straight from secret_versions/secrets, never synthesized from the
  // current version count the way this list used to be built.
  const versions = versionsQuery.data?.data ?? []

  // Visual-only "copied" confirmation per field (a brief checkmark swap —
  // see the render below). Deliberately not an attempt to clear the OS
  // clipboard on a timer: there is no reliable, standard way to do that
  // from a web page, and forcibly overwriting the clipboard after N
  // seconds risks silently discarding something the user copied
  // afterward, which is worse than not clearing it at all. Explicit
  // action, a clear one-time confirmation, and never auto-copying is the
  // achievable, honest version of "handle the clipboard carefully" here.
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  useEffect(() => {
    if (copiedKey === null) return
    const timer = setTimeout(() => setCopiedKey(null), 1500)
    return () => clearTimeout(timer)
  }, [copiedKey])

  function handleReveal() {
    setViewingVersion(selectedVersion)
    void reveal.refetch()
  }

  async function handleCopy(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value)
      // "Secret copied to clipboard." — deliberately never the value
      // itself, matching the same principle useRevealSecret's own doc
      // comment already holds this component to everywhere else.
      toast.success("Secret copied to clipboard.")
      setCopiedKey(key)
    } catch {
      toast.error("Could not copy — your browser may be blocking clipboard access.")
    }
  }

  function toggleMask(key: string) {
    setMaskedFields((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  // True once at least one field of a revealed version is currently
  // shown in plaintext — drives the "Secret value visible" notice below.
  // maskedFields (despite its name) holds the keys the user has chosen to
  // *un*-mask — see toggleMask/isMasked below.
  const anyFieldVisible = maskedFields.size > 0

  return (
    <Sheet open={path !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader>
          <div className="flex items-center gap-2">
            <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
              <Lock className="size-4" strokeWidth={1.75} aria-hidden="true" />
            </span>
            <SheetTitle className="min-w-0 truncate font-mono">{path ?? "Secret details"}</SheetTitle>
          </div>
          <SheetDescription className="flex items-center gap-2">
            <span>{secret ? `Current version: ${secret.version}` : "Loading…"}</span>
            {secret && (
              <span className="flex items-center gap-1 text-xs font-medium text-kanz-success">
                <span className="size-1.5 rounded-full bg-kanz-success" aria-hidden="true" />
                Protected
              </span>
            )}
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-6 overflow-y-auto px-4 pb-6">
          {!secret && (
            <div className="flex flex-col gap-3">
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-full" />
            </div>
          )}

          {secret && (
            <>
              <section className="flex flex-col gap-2">
                <Row label="Created">
                  <span className="text-xs">{new Date(secret.created_at).toLocaleString()}</span>
                </Row>
                <Row label="Updated">
                  <span className="text-xs">{new Date(secret.updated_at).toLocaleString()}</span>
                </Row>
                <Row label="Path">
                  <span className="max-w-[60%] truncate text-right font-mono text-xs">{secret.path}</span>
                </Row>
              </section>

              <section className="flex flex-col gap-2 border-t pt-4">
                <h3 className="text-sm font-medium">Version history</h3>

                {versionsQuery.isLoading && (
                  <div className="flex flex-col gap-1.5">
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-10 w-full" />
                  </div>
                )}
                {versionsQuery.isError && (
                  <p className="text-xs text-muted-foreground">Could not load version history.</p>
                )}

                <ul className="flex flex-col gap-1">
                  {versions.map((v) => (
                    <li key={v.version}>
                      <div
                        className={cn(
                          "flex w-full items-center justify-between gap-2 rounded-lg border px-2.5 py-1.5 text-sm transition-colors",
                          selectedVersion === v.version && "border-kanz-primary/30 bg-kanz-primary/5",
                        )}
                      >
                        <button
                          type="button"
                          onClick={() => setViewingVersion(v.version)}
                          className="flex min-w-0 flex-1 flex-col items-start gap-0.5 text-left hover:opacity-80"
                          aria-pressed={selectedVersion === v.version}
                        >
                          <span className="flex items-center gap-2">
                            <span>Version {v.version}</span>
                            {v.current && <Badge variant="default">Current</Badge>}
                          </span>
                          <span className="truncate text-xs text-muted-foreground">
                            {formatRelativeTime(v.created_at)} · by {v.created_by.slice(0, 8)}…
                          </span>
                        </button>
                        {canRollback && !v.current && (
                          <Button
                            size="sm"
                            variant="outline"
                            className="shrink-0"
                            onClick={() => setConfirmingRollbackVersion(v.version)}
                          >
                            <RotateCcw className="size-3.5" aria-hidden="true" />
                            Rollback to this version
                          </Button>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </section>

              <section className="flex flex-col gap-3 border-t pt-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium">
                    Secret Value <span className="text-muted-foreground">(version {selectedVersion})</span>
                  </h3>
                  {canRead && (
                    <Button size="sm" variant="outline" onClick={handleReveal} disabled={reveal.isFetching}>
                      {reveal.isFetching
                        ? "Revealing…"
                        : viewingVersion !== null && reveal.data
                          ? "Refresh"
                          : "Reveal secret"}
                    </Button>
                  )}
                </div>

                {!canRead && (
                  <p className="text-sm text-muted-foreground">
                    You don't have permission to reveal this secret's value.
                  </p>
                )}

                {reveal.isFetching && (
                  <div className="flex flex-col gap-2">
                    <Skeleton className="h-8 w-full" />
                    <Skeleton className="h-8 w-full" />
                  </div>
                )}

                {reveal.isError && (
                  <p role="alert" className="text-sm text-destructive">
                    {friendlyErrorMessage(reveal.error)}
                  </p>
                )}

                {reveal.data && reveal.data.version === selectedVersion && !reveal.isFetching && (
                  <div className="flex flex-col gap-2">
                    {anyFieldVisible && (
                      <p className="flex items-center gap-1.5 text-xs font-medium text-kanz-warning">
                        <AlertTriangle className="size-3.5 shrink-0" aria-hidden="true" />
                        Secret value visible
                      </p>
                    )}
                    <ul className="flex flex-col gap-2">
                      {Object.entries(reveal.data.data).map(([key, value]) => {
                        const isMasked = !maskedFields.has(key)
                        return (
                          <li
                            key={key}
                            className="flex items-center gap-2 rounded-lg border border-border bg-kanz-surface-elevated/40 px-2.5 py-1.5 transition-[border-color] duration-150"
                          >
                            <span className="w-1/3 shrink-0 truncate text-sm font-medium">{key}</span>
                            <span
                              className={cn(
                                "flex-1 truncate font-mono text-sm",
                                isMasked ? "text-muted-foreground" : "text-foreground",
                              )}
                            >
                              {isMasked ? "•".repeat(Math.min(value.length, 24)) || "•" : value}
                            </span>
                            <button
                              type="button"
                              onClick={() => toggleMask(key)}
                              className="text-muted-foreground transition-colors hover:text-kanz-primary"
                              aria-label={isMasked ? `Show ${key}` : `Hide ${key}`}
                              aria-pressed={!isMasked}
                            >
                              {isMasked ? <Eye className="size-3.5" /> : <EyeOff className="size-3.5" />}
                            </button>
                            <button
                              type="button"
                              onClick={() => void handleCopy(key, value)}
                              className="text-muted-foreground transition-colors hover:text-kanz-primary"
                              aria-label={`Copy ${key} to clipboard`}
                            >
                              {copiedKey === key ? (
                                <Check className="size-3.5 text-kanz-success" />
                              ) : (
                                <Copy className="size-3.5" />
                              )}
                            </button>
                          </li>
                        )
                      })}
                    </ul>
                  </div>
                )}
              </section>

              <section className="flex flex-col gap-2 border-t pt-4">
                {canUpdate && (
                  <Button
                    variant="outline"
                    onClick={() => setUpdateOpen(true)}
                    disabled={selectedVersion !== secret.version}
                  >
                    Update secret
                  </Button>
                )}
                {canUpdate && selectedVersion !== secret.version && (
                  <p className="text-xs text-muted-foreground">
                    Select the current version to update this secret.
                  </p>
                )}
                {canDelete && (
                  <Button variant="destructive" onClick={() => setConfirmingDelete(true)}>
                    <Trash2 className="size-4" aria-hidden="true" />
                    Delete secret
                  </Button>
                )}
              </section>

              <section className="flex flex-col gap-2 border-t pt-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium">Security Activity</h3>
                  <Link
                    to="/audit"
                    className="flex items-center gap-1 text-xs font-medium text-kanz-primary transition-colors hover:text-kanz-primary-glow"
                  >
                    View in Audit Explorer
                    <ArrowRight className="size-3" aria-hidden="true" />
                  </Link>
                </div>

                {activity.isLoading && (
                  <div className="flex flex-col gap-1.5">
                    <Skeleton className="h-8 w-full" />
                    <Skeleton className="h-8 w-full" />
                  </div>
                )}

                {!activity.isLoading && activity.isError && (
                  <p className="text-xs text-muted-foreground">Could not load security activity.</p>
                )}

                {!activity.isLoading && !activity.isError && activity.data?.data.length === 0 && (
                  <div className="flex items-center gap-2 rounded-lg border border-dashed border-border px-3 py-4 text-xs text-muted-foreground">
                    <History className="size-4 shrink-0" strokeWidth={1.5} aria-hidden="true" />
                    No recorded activity for this secret yet.
                  </div>
                )}

                {!activity.isLoading && !activity.isError && activity.data && activity.data.data.length > 0 && (
                  <ul className="flex flex-col gap-1">
                    {activity.data.data.map((event) => {
                      const EventIcon = iconForAuditAction(event.action)
                      return (
                        <li key={event.id} className="flex items-center gap-2.5 rounded-lg px-1.5 py-1.5 text-sm">
                          <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-kanz-surface-elevated text-kanz-primary">
                            <EventIcon className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                          </span>
                          <span className="min-w-0 flex-1 truncate font-mono text-xs">{event.action}</span>
                          <span className={cn("shrink-0 text-xs font-medium", RESULT_CLASS[event.result])}>
                            {event.result}
                          </span>
                          <span className="shrink-0 text-[0.65rem] text-muted-foreground">
                            {formatRelativeTime(event.occurred_at)}
                          </span>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </section>
            </>
          )}
        </div>
      </SheetContent>

      {secret && (
        <UpdateSecretDialog
          path={secret.path}
          currentVersion={secret.version}
          initialData={reveal.data && reveal.data.version === secret.version ? reveal.data.data : null}
          open={updateOpen}
          onOpenChange={setUpdateOpen}
        />
      )}

      <AlertDialog open={confirmingDelete} onOpenChange={setConfirmingDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete secret "{path}"?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone from normal access — its encrypted history is
              retained, not permanently destroyed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleteSecret.isPending}
              onClick={() => {
                if (!path) return
                deleteSecret.mutate(path, {
                  onSuccess: () => {
                    toast.success(`Secret "${path}" deleted.`)
                    setConfirmingDelete(false)
                    onOpenChange(false)
                  },
                  onError: (error) => {
                    toast.error(friendlyErrorMessage(error))
                    setConfirmingDelete(false)
                  },
                })
              }}
            >
              {deleteSecret.isPending ? "Deleting…" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={confirmingRollbackVersion !== null}
        onOpenChange={(open) => !open && setConfirmingRollbackVersion(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Create a new version using the value from Version {confirmingRollbackVersion}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This creates a new version — Version {secret?.version} and every other historical
              version remain exactly as they are, nothing is deleted or overwritten.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={rollback.isPending}
              onClick={() => {
                if (confirmingRollbackVersion === null || !secret) return
                rollback.mutate(
                  { targetVersion: confirmingRollbackVersion, expectedVersion: secret.version },
                  {
                    onSuccess: (updated) => {
                      toast.success(`New version created — Version ${updated.version} is now current.`)
                      setConfirmingRollbackVersion(null)
                      setViewingVersion(null)
                    },
                    onError: (error) => {
                      toast.error(friendlyErrorMessage(error))
                      setConfirmingRollbackVersion(null)
                    },
                  },
                )
              }}
            >
              {rollback.isPending ? "Rolling back…" : "Roll back"}
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
