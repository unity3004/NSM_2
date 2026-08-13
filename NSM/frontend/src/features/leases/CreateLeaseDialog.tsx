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
import { Switch } from "@/components/ui/switch"
import { useCreateLease } from "@/features/leases/useLeaseMutations"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { Timer, TriangleAlert, Copy, Check } from "lucide-react"
import { toast } from "sonner"

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
  const [copied, setCopied] = useState(false)
  const createLease = useCreateLease()

  function reset() {
    setType("dev-credential")
    setPath("")
    setRole("")
    setTtl("")
    setRenewable(false)
    setTouched(false)
    setCopied(false)
    createLease.reset()
  }

  const pathError = touched && path.trim() === "" ? "Path is required." : null
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

  async function handleCopy(secret: string) {
    try {
      await navigator.clipboard.writeText(secret)
      toast.success("Copied to clipboard.")
      setCopied(true)
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
          <Timer />
          New lease
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        {!created ? (
          <form onSubmit={handleSubmit}>
            <DialogHeader>
              <DialogTitle>Request a dynamic secret lease</DialogTitle>
              <DialogDescription>
                Issues a temporary credential with a bounded lifetime. The credential will only be
                shown once, immediately after creation — it cannot be retrieved again.
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-col gap-4 py-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lease-type">Type</Label>
                <Input
                  id="lease-type"
                  value={type}
                  onChange={(event) => setType(event.target.value)}
                  placeholder="dev-credential"
                />
                <p className="text-xs text-muted-foreground">
                  The registered dynamic-credential provider to use.
                </p>
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lease-path">Path</Label>
                <Input
                  id="lease-path"
                  autoFocus
                  placeholder="database/prod/readonly"
                  value={path}
                  onChange={(event) => setPath(event.target.value)}
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
                  placeholder="payment-readonly"
                  value={role}
                  onChange={(event) => setRole(event.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Selects a pre-approved role template from an operator-configured catalog — e.g.
                  a Postgres provider's least-privilege database role. Required for providers that
                  need one; ignored otherwise.
                </p>
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lease-ttl">TTL (optional)</Label>
                <Input
                  id="lease-ttl"
                  placeholder="30m"
                  value={ttl}
                  onChange={(event) => setTtl(event.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Go duration syntax (e.g. "30m", "1h"). Leave blank to use the server default —
                  requests above the server's configured maximum are clamped down, never rejected.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <Switch id="lease-renewable" checked={renewable} onCheckedChange={setRenewable} />
                <Label htmlFor="lease-renewable" className="font-normal">
                  Renewable
                </Label>
              </div>

              {createLease.isError && (
                <p role="alert" className="text-sm text-destructive">
                  {friendlyErrorMessage(createLease.error)}
                </p>
              )}
            </div>

            <DialogFooter>
              <Button type="submit" disabled={createLease.isPending}>
                <Timer />
                {createLease.isPending ? "Requesting…" : "Request lease"}
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Lease created</DialogTitle>
              <DialogDescription>
                Copy this credential now. It will never be shown again — this dialog is the only
                place it ever appears.
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-col gap-4 py-4">
              <div className="flex items-start gap-3 rounded-lg border border-destructive/50 bg-destructive/10 p-3">
                <TriangleAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
                <div className="flex flex-col gap-1">
                  <p className="text-sm font-medium text-destructive">
                    This credential will not be displayed again.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    Store it now. Neither this page nor the backend can display it again — if it's
                    lost, revoke this lease and request a new one.
                  </p>
                </div>
              </div>

              <div className="flex flex-col gap-3">
                {Object.entries(created.credential).map(([key, value]) => (
                  <div key={key} className="flex flex-col gap-1.5">
                    <Label className="capitalize">{key}</Label>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 overflow-x-auto rounded-md border bg-muted px-2 py-1.5 text-xs">
                        {value}
                      </code>
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        aria-label={`Copy ${key} to clipboard`}
                        onClick={() => void handleCopy(value)}
                      >
                        {copied ? <Check className="text-green-600" /> : <Copy />}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <DialogFooter>
              <Button
                onClick={() => {
                  setOpen(false)
                  reset()
                }}
              >
                Done — I've stored it
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
