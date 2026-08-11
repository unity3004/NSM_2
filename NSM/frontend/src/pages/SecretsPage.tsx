import { useMemo, useState } from "react"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useSecrets } from "@/features/secrets/useSecrets"
import { CreateSecretDialog } from "@/features/secrets/CreateSecretDialog"
import { SecretDetailSheet } from "@/features/secrets/SecretDetailSheet"
import { usePermission } from "@/features/auth/usePermission"
import { formatRelativeTime } from "@/lib/utils"

// REAL API DATA: every row comes straight from GET /v1/secrets
// (secrets:list-gated by the real backend) — metadata only. No secret
// value, ciphertext, or key ever appears on this page; SecretResponse (the
// type this list is built from) has no field that could hold one. Search
// below filters this already-fetched metadata client-side — it never
// triggers a second request, and there is no decrypted value anywhere in
// the data being filtered for it to search over.
export function SecretsPage() {
  const { data, isLoading, isError } = useSecrets()
  const [search, setSearch] = useState("")
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const canCreate = usePermission("secrets:create")

  const filtered = useMemo(() => {
    const secrets = data?.data ?? []
    const q = search.trim().toLowerCase()
    if (!q) return secrets
    return secrets.filter((s) => s.path.toLowerCase().includes(q))
  }, [data, search])

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Secrets</h1>
          <p className="text-sm text-muted-foreground">
            Encrypted key/value credentials, scoped to this organization. Values are never shown
            here — open a secret and reveal it explicitly.
          </p>
        </div>
        {canCreate && <CreateSecretDialog />}
      </div>

      <Input
        placeholder="Search by path…"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        className="max-w-sm"
        aria-label="Search secrets"
      />

      {isError && (
        <p className="text-sm text-muted-foreground">
          You don't have permission to view secrets, or something went wrong.
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
                <TableHead>Path</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-sm text-muted-foreground">
                    No secrets found.
                  </TableCell>
                </TableRow>
              )}
              {filtered.map((secret) => (
                <TableRow
                  key={secret.path}
                  className="cursor-pointer"
                  onClick={() => setSelectedPath(secret.path)}
                >
                  <TableCell className="font-mono text-sm font-medium">{secret.path}</TableCell>
                  <TableCell>
                    <Badge variant="outline">v{secret.version}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatRelativeTime(secret.updated_at)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {new Date(secret.created_at).toLocaleDateString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <SecretDetailSheet path={selectedPath} onOpenChange={(open) => !open && setSelectedPath(null)} />
    </div>
  )
}
