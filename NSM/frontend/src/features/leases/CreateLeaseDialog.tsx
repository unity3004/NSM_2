import { useState, type FormEvent } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { useCreateLease } from "@/features/leases/useLeaseMutations"
import { useCountdown } from "@/features/leases/useCountdown"
import { LEASE_TYPE_LABELS } from "@/features/leases/leaseDisplay"
import { ApiError } from "@/lib/apiError"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { Zap, TriangleAlert, Copy, Check, Lock } from "lucide-react"
import { toast } from "sonner"

const LEASE_TYPES: { value: string; label: string }[] = Object.entries(LEASE_TYPE_LABELS).map(([value, label]) => ({
  value,
  label,
}))

/**
 * Creates a lease and — once, immediately after creation — shows the raw
 * dynamic credential with an explicit "shown only once" warning, the same
 * guarantee CreateCredentialDialog (service accounts) already makes for
 * API-key secrets. The credential was never persisted anywhere the
 * frontend can read it back from: only LeaseCreatedResponse.credential,
 * present in this one HTTP response body, ever carried it. Closing this
 * dialog is the point of no return — revoking the lease and creating a
 * new one is the only recovery from a lost credential.
 */
export function CreateLeaseDialog() {
  const [open, setOpen] = useState(false)
  const [type, setType] = useState("dev-credential")
  const [path, setPath] = useState("")
  const [role, setRole] = useState("")
  const [ttl, setTtl] = useState("")
  const [renewable, setRenewable] = useState(false)
  const [touched, setTouched] = useState(false)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const createLease = useCreateLease()

  function reset() {
    setType("dev-credential")
    setPath("")
    setRole("")
    setTtl("")
    setRenewable(false)
    setTouched(false)
    setCopiedKey(null)
    createLease.reset()
  }

  const fieldErrors = new Map<string, string>()
  if (createLease.error instanceof ApiError && createLease.error.details) {
    for (const detail of createLease.error.details) {
      fieldErrors.set(detail.field, detail.issue)
    }
  }

  const pathError =
    (touched && path.trim() === "" ? "Path is required." : null) ?? fieldErrors.get("path") ?? null
  const roleError = fieldErrors.get("role") ?? null
  const ttlError = fieldErrors.get("ttl") ?? null
  const isValid = path.trim() !== ""

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (!isValid) return
    createLease.mutate({
      type: type.trim(),
      path: path.trim(),
      role: role.trim() || undefined,
      ttl: ttl.trim() || undefined,
      renewable,
    })
  }

  async function handleCopy(key: string, value: string) {
    try {
      await navigator.clipboard.writeText(value)
      // Never the value itself — see the same principle SecretDetailSheet's
      // own copy handler holds to.
      toast.success("Credential copied to clipboard.")
      setCopiedKey(key)
    } catch {
      toast.error("Could not copy — your browser may be blocking clipboard access.")
    }
  }

  const created = createLease.data

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) reset()
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <Zap />
          Request Lease
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        {!created ? (
          <form onSubmit={handleSubmit}>
            <DialogHeader>
              <DialogTitle>Request Temporary Credential</DialogTitle>
              <DialogDescription>
                KANZ will issue a temporary credential with a bounded lifetime. The credential
                will be shown once, immediately after creation — it cannot be retrieved again.
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-col gap-4 py-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lease-type">Type</Label>
                <Select value={type} onValueChange={setType}>
                  <SelectTrigger id="lease-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {LEASE_TYPES.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  The registered dynamic-credential provider to use.
                </p>
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lease-path">Resource</Label>
                <Input
                  id="lease-path"
                  autoFocus
                  placeholder="infra/postgres/demo"
                  value={path}
                  onChange={(event) => setPath(event.target.value)}
                  className="font-mono"
                  aria-invalid={!!pathError}
                />
                {pathError && (
                  <p role="alert" className="text-sm text-destructive">
                    {pathError}
                  </p>
                )}
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lease-role">Role (optional)</Label>
                <Input
                  id="lease-role"
                  placeholder="demo-readonly"
                  value={role}
                  onChange={(event) => setRole(event.target.value)}
                  aria-invalid={!!roleError}
                />
                <p className="text-xs text-muted-foreground">
                  Selects a pre-approved role template from an operator-configured catalog — e.g.
                  a Postgres provider's least-privilege database role. Required for providers that
                  need one; ignored otherwise.
                </p>
                {roleError && (
                  <p role="alert" className="text-sm text-destructive">
                    {roleError}
                  </p>
                )}
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lease-ttl">TTL (optional)</Label>
                <Input
                  id="lease-ttl"
                  placeholder="10m"
                  value={ttl}
                  onChange={(event) => setTtl(event.target.value)}
                  aria-invalid={!!ttlError}
                />
                <p className="text-xs text-muted-foreground">
                  Go duration syntax (e.g. "10m", "1h"). Leave blank to use the server default —
                  requests above the server's configured maximum are clamped down, never rejected.
                </p>
                {ttlError && (
                  <p role="alert" className="text-sm text-destructive">
                    {ttlError}
                  </p>
                )}
              </div>

              <div className="flex items-center gap-2">
                <Switch id="lease-renewable" checked={renewable} onCheckedChange={setRenewable} />
                <Label htmlFor="lease-renewable" className="font-normal">
                  Renewable
                </Label>
              </div>

              <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Lock className="size-3 shrink-0 text-kanz-primary" aria-hidden="true" />
                The credential will be shown once after creation, then never again.
              </p>

              {createLease.isError && (
                <p role="alert" className="text-sm text-destructive">
                  {friendlyErrorMessage(createLease.error)}
                </p>
              )}
            </div>

            <DialogFooter>
              <Button type="submit" disabled={createLease.isPending}>
                <Zap />
                {createLease.isPending ? "Requesting…" : "Request lease"}
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <CredentialIssued created={created} copiedKey={copiedKey} onCopy={handleCopy} onDone={() => { setOpen(false); reset() }} />
        )}
      </DialogContent>
    </Dialog>
  )
}

function CredentialIssued({
  created,
  copiedKey,
  onCopy,
  onDone,
}: {
  created: NonNullable<ReturnType<typeof useCreateLease>["data"]>
  copiedKey: string | null
  onCopy: (key: string, value: string) => void
  onDone: () => void
}) {
  const countdown = useCountdown(created.expires_at, true)

  return (
    <>
      <DialogHeader>
        <div className="flex items-center gap-2">
          <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-kanz-success/10 text-kanz-success">
            <Check className="size-4" strokeWidth={2} aria-hidden="true" />
          </span>
          <DialogTitle>Temporary Credential Issued</DialogTitle>
        </div>
        <DialogDescription>
          <span className="mb-0.5 block font-medium text-foreground">{LEASE_TYPE_LABELS[created.lease_type] ?? created.lease_type}</span>
          <span className="font-mono text-xs">{created.resource_path}</span>
        </DialogDescription>
      </DialogHeader>

      <div className="flex flex-col gap-4 py-4">
        <div className="flex items-start gap-3 rounded-lg border border-kanz-warning/30 bg-kanz-warning/10 p-3">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-kanz-warning" aria-hidden="true" />
          <div className="flex flex-col gap-1">
            <p className="text-sm font-medium text-kanz-warning">Save this credential now.</p>
            <p className="text-sm text-muted-foreground">
              KANZ will not display this credential again after you leave this screen. If it's
              lost, revoke this lease and request a new one.
            </p>
          </div>
        </div>

        <div className="flex flex-col gap-3">
          {Object.entries(created.credential).map(([key, value]) => (
            <div key={key} className="flex flex-col gap-1.5">
              <Label className="capitalize">{key}</Label>
              <div className="flex items-center gap-2">
                <code className="flex-1 overflow-x-auto rounded-md border border-border bg-kanz-surface-elevated px-2 py-1.5 text-xs">
                  {value}
                </code>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  aria-label={`Copy ${key} to clipboard`}
                  onClick={() => onCopy(key, value)}
                >
                  {copiedKey === key ? <Check className="size-3.5 text-kanz-success" /> : <Copy className="size-3.5" />}
                  {copiedKey === key ? "Copied" : `Copy ${key}`}
                </Button>
              </div>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-1 rounded-lg border border-border bg-kanz-surface-elevated/50 px-3 py-2">
          <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">Expires in</span>
          <span className="font-mono text-sm text-foreground">{countdown.label.replace("Expires in ", "")}</span>
        </div>
      </div>

      <DialogFooter>
        <Button onClick={onDone}>Done — I've stored it</Button>
      </DialogFooter>
    </>
  )
}
