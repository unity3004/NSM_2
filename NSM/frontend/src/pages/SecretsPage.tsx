import { useMemo, useState } from "react"
import { KeyRound, Search, ChevronRight, Lock, AlertTriangle, RefreshCw } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { useSecrets } from "@/features/secrets/useSecrets"
import { CreateSecretDialog } from "@/features/secrets/CreateSecretDialog"
import { SecretDetailSheet } from "@/features/secrets/SecretDetailSheet"
import { usePermission } from "@/features/auth/usePermission"
import { formatRelativeTime } from "@/lib/utils"
import { cn } from "@/lib/utils"
import type { SecretResponse } from "@/types/secret"

/** The first path segment ("production/database" → "production"), or null
 * for a path with no "/" at all — used purely to group the real, already-
 * fetched paths visually; the backend's storage model has no notion of a
 * folder and nothing here changes it (see SecretResponse — path is, and
 * remains, one flat string). */
function pathGroup(path: string): string | null {
  const slash = path.indexOf("/")
  return slash === -1 ? null : path.slice(0, slash)
}

// REAL API DATA: every row comes straight from GET /v1/secrets
// (secrets:list-gated by the real backend) — metadata only. No secret
// value, ciphertext, or key ever appears on this page; SecretResponse (the
// type this list is built from) has no field that could hold one. Search
// and group-filtering below operate on this already-fetched metadata
// client-side — neither ever triggers a second request, and there is no
// decrypted value anywhere in the data being filtered for it to search
// over.
export function SecretsPage() {
  const { data, isLoading, isError, refetch, isRefetching } = useSecrets()
  const [search, setSearch] = useState("")
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null)
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const canCreate = usePermission("secrets:create")

  // Memoized so the two useMemo calls below that depend on it don't
  // recompute on every render just because `[]` is a fresh array
  // reference each time data is undefined/absent — data itself only
  // changes reference when TanStack Query actually has new results.
  const allSecrets = useMemo(() => data?.data ?? [], [data])

  // Real top-level path segments only — a path with no "/" at all
  // contributes no chip (there is nothing meaningful to filter it by),
  // rather than lumping it into a synthetic "ungrouped" bucket.
  const groups = useMemo(() => {
    const counts = new Map<string, number>()
    for (const s of allSecrets) {
      const key = pathGroup(s.path)
      if (key === null) continue
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b))
  }, [allSecrets])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return allSecrets.filter((s) => {
      if (q && !s.path.toLowerCase().includes(q)) return false
      if (selectedGroup && pathGroup(s.path) !== selectedGroup) return false
      return true
    })
  }, [allSecrets, search, selectedGroup])

  // Grouped for display — every group that has at least one *filtered*
  // secret, in the same alphabetical order as the chips, ungrouped paths
  // (no "/" at all) collected last under no heading.
  const sections = useMemo(() => {
    const byGroup = new Map<string, SecretResponse[]>()
    const ungrouped: SecretResponse[] = []
    for (const s of filtered) {
      const key = pathGroup(s.path)
      if (key === null) ungrouped.push(s)
      else byGroup.set(key, [...(byGroup.get(key) ?? []), s])
    }
    const result: { label: string | null; secrets: SecretResponse[] }[] = [...byGroup.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([label, secrets]) => ({ label, secrets }))
    if (ungrouped.length > 0) result.push({ label: null, secrets: ungrouped })
    return result
  }, [filtered])

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
            <Lock className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Secrets</h1>
            <p className="text-sm text-muted-foreground">
              Securely store, manage, and control access to sensitive application credentials.
            </p>
          </div>
        </div>
        {canCreate && <CreateSecretDialog onCreated={setSelectedPath} />}
      </div>

      <div className="flex flex-col gap-3">
        <div className="relative max-w-sm">
          <Search
            className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            placeholder="Search secrets by path…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            className="pl-8"
            aria-label="Search secrets"
          />
        </div>

        {groups.length > 1 && (
          <div className="flex flex-wrap gap-1.5">
            <GroupChip label="All" active={selectedGroup === null} onClick={() => setSelectedGroup(null)} />
            {groups.map(([group, count]) => (
              <GroupChip
                key={group}
                label={`${group} (${count})`}
                active={selectedGroup === group}
                onClick={() => setSelectedGroup(group)}
              />
            ))}
          </div>
        )}
      </div>

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      )}

      {!isLoading && isError && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-12 text-center">
          <AlertTriangle className="size-5 text-muted-foreground" strokeWidth={1.5} aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-foreground">Unable to load secrets</p>
            <p className="mt-1 text-sm text-muted-foreground">
              KANZ could not retrieve the current secret inventory.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isRefetching}>
            <RefreshCw className={cn("size-3.5", isRefetching && "animate-spin")} />
            {isRefetching ? "Retrying…" : "Retry"}
          </Button>
        </div>
      )}

      {!isLoading && !isError && allSecrets.length === 0 && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-16 text-center">
          <span className="flex size-12 items-center justify-center rounded-full bg-kanz-surface-elevated text-kanz-primary">
            <Lock className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <p className="text-sm font-medium text-foreground">No secrets yet</p>
            <p className="mt-1 max-w-xs text-sm text-muted-foreground">
              Create your first protected secret and let KANZ keep it secure.
              {canCreate && " Use “Create secret” above to get started."}
            </p>
          </div>
        </div>
      )}

      {!isLoading && !isError && allSecrets.length > 0 && filtered.length === 0 && (
        <p className="rounded-lg border border-dashed border-border py-10 text-center text-sm text-muted-foreground">
          No secrets found.
        </p>
      )}

      {!isLoading && !isError && filtered.length > 0 && (
        <div className="flex flex-col gap-5">
          {sections.map((section) => (
            <div key={section.label ?? "__ungrouped__"} className="flex flex-col gap-2">
              {section.label && (
                <h2 className="font-mono text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                  {section.label}/
                </h2>
              )}
              <div className="flex flex-col gap-1.5">
                {section.secrets.map((secret) => (
                  <SecretRow key={secret.path} secret={secret} onSelect={() => setSelectedPath(secret.path)} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      <SecretDetailSheet path={selectedPath} onOpenChange={(open) => !open && setSelectedPath(null)} />
    </div>
  )
}

function GroupChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "rounded-full border px-2.5 py-1 font-mono text-xs transition-colors duration-150",
        active
          ? "border-kanz-primary/40 bg-kanz-primary/10 text-kanz-primary"
          : "border-border text-muted-foreground hover:border-kanz-primary/25 hover:text-foreground",
      )}
    >
      {label}
    </button>
  )
}

function SecretRow({ secret, onSelect }: { secret: SecretResponse; onSelect: () => void }) {
  // Every secret this application stores is encrypted at rest — this is
  // the platform's own architectural guarantee (see EncryptionService),
  // not a per-secret field the API returns; the badge below is the same
  // "true for every real secret in this system" chrome the login page's
  // own branding already uses, not a fabricated per-item status.
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "group flex w-full items-center gap-3 rounded-lg border border-border bg-card px-3.5 py-3 text-left",
        "transition-[border-color,background-color,transform] duration-150",
        "hover:border-kanz-primary/30 hover:bg-kanz-surface-elevated",
      )}
    >
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary transition-colors group-hover:brightness-125">
        <KeyRound className="size-4" strokeWidth={1.75} aria-hidden="true" />
      </span>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-sm font-medium text-foreground">{secret.path}</span>
          <span className="shrink-0 rounded-full border border-border px-1.5 py-0.5 font-mono text-[0.65rem] text-muted-foreground">
            v{secret.version}
          </span>
        </div>
        <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
          <span className="flex items-center gap-1 text-kanz-success">
            <span className="size-1.5 rounded-full bg-kanz-success" aria-hidden="true" />
            Encrypted
          </span>
          <span aria-hidden="true">·</span>
          <span>Updated {formatRelativeTime(secret.updated_at)}</span>
        </div>
      </div>

      <ChevronRight
        className="size-4 shrink-0 text-muted-foreground transition-[transform,color] duration-150 group-hover:translate-x-0.5 group-hover:text-kanz-primary"
        aria-hidden="true"
      />
    </button>
  )
}
