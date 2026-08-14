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
import { useCreateSecret } from "@/features/secrets/useCreateSecret"
import { useSecretFieldsEditor } from "@/features/secrets/useSecretFieldsEditor"
import { SecretFieldsEditor } from "@/features/secrets/SecretFieldsEditor"
import { ApiError } from "@/lib/apiError"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { KeyRound, Lock, CheckCircle2 } from "lucide-react"
import { toast } from "sonner"
import type { SecretResponse } from "@/types/secret"

// Mirrors the path rules the backend actually enforces
// (util.ValidateSecretPath) — validated here only so a malformed path is
// caught before a round trip, with a specific message; the backend
// re-checks authoritatively regardless of what this client-side copy says.
const VALID_PATH_SEGMENT = /^[A-Za-z0-9._-]+$/
const MAX_PATH_LENGTH = 1024

function validatePath(path: string): string | null {
  const trimmed = path.trim().replace(/^\/+|\/+$/g, "")
  if (trimmed === "") return "Path is required."
  if (trimmed.length > MAX_PATH_LENGTH) return `Path must be at most ${MAX_PATH_LENGTH} characters.`
  for (const segment of trimmed.split("/")) {
    if (segment === "") return 'Path must not contain empty segments ("//").'
    if (segment === "." || segment === "..") return 'Path must not contain "." or ".." segments.'
    if (!VALID_PATH_SEGMENT.test(segment)) {
      return "Path may only contain letters, digits, '.', '_', '-', and '/' as a separator."
    }
  }
  return null
}

function friendlyCreateError(error: unknown): string {
  if (error instanceof ApiError && error.code === "CONFLICT") {
    return "A secret already exists at this path."
  }
  return friendlyErrorMessage(error)
}

/** `onCreated` is optional and purely a navigation convenience (the
 * confirmation view's "View Secret" button) — SecretsPage passes its own
 * setSelectedPath so that button can open the real detail sheet; nothing
 * about creation itself depends on it, and every other call site (or a
 * test rendering this component bare) works identically without it. */
export function CreateSecretDialog({ onCreated }: { onCreated?: (path: string) => void }) {
  const [open, setOpen] = useState(false)
  const [path, setPath] = useState("")
  const [touched, setTouched] = useState(false)
  // Set only on a successful creation — while non-null, the dialog shows
  // the confirmation view instead of the form. The API response itself
  // (SecretResponse) has no field that could ever hold the value that was
  // just submitted, so there is no way for this confirmation to leak it
  // even by accident.
  const [justCreated, setJustCreated] = useState<SecretResponse | null>(null)
  const editor = useSecretFieldsEditor()
  const createSecret = useCreateSecret()

  const pathError = touched ? validatePath(path) : null

  function reset() {
    setPath("")
    editor.reset()
    setTouched(false)
    setJustCreated(null)
    createSecret.reset()
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (validatePath(path) !== null || !editor.isValid) {
      return
    }
    const normalizedPath = path.trim().replace(/^\/+|\/+$/g, "")
    createSecret.mutate(
      { path: normalizedPath, data: editor.payload },
      {
        onSuccess: (created) => {
          toast.success(`Secret "${created.path}" created.`)
          setJustCreated(created)
        },
      },
    )
  }

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
          <KeyRound />
          Create secret
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        {justCreated ? (
          <>
            <div className="flex flex-col items-center gap-3 py-4 text-center">
              <span className="flex size-12 items-center justify-center rounded-full bg-kanz-success/10 text-kanz-success">
                <CheckCircle2 className="size-6" strokeWidth={1.75} aria-hidden="true" />
              </span>
              <div>
                <p className="text-base font-semibold text-foreground">Secret secured</p>
                <p className="mt-1 font-mono text-sm text-kanz-primary">{justCreated.path}</p>
              </div>
              <p className="max-w-xs text-sm text-muted-foreground">
                The secret has been encrypted and stored securely.
              </p>
            </div>
            <DialogFooter className="sm:justify-center">
              <Button
                variant="outline"
                onClick={() => {
                  setOpen(false)
                  reset()
                }}
              >
                Back to Secrets
              </Button>
              <Button
                onClick={() => {
                  const created = justCreated
                  setOpen(false)
                  reset()
                  if (created) onCreated?.(created.path)
                }}
              >
                View Secret
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={handleSubmit}>
            <DialogHeader>
              <DialogTitle>Create secret</DialogTitle>
              <DialogDescription>Secure a new application credential or sensitive value.</DialogDescription>
            </DialogHeader>

            <div className="flex flex-col gap-4 py-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="new-secret-path">Path</Label>
                <Input
                  id="new-secret-path"
                  autoFocus
                  placeholder="prod/database"
                  value={path}
                  onChange={(event) => setPath(event.target.value)}
                  aria-invalid={!!pathError}
                  aria-describedby={pathError ? "new-secret-path-error" : undefined}
                  className="font-mono"
                />
                {pathError && (
                  <p id="new-secret-path-error" role="alert" className="text-sm text-destructive">
                    {pathError}
                  </p>
                )}
              </div>

              <div className="flex flex-col gap-2">
                <Label>Data</Label>
                <SecretFieldsEditor editor={editor} touched={touched} />
              </div>

              <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Lock className="size-3 shrink-0 text-kanz-primary" aria-hidden="true" />
                Secret will be encrypted and protected by KANZ.
              </p>

              {createSecret.isError && (
                <p role="alert" className="text-sm text-destructive">
                  {friendlyCreateError(createSecret.error)}
                </p>
              )}
            </div>

            <DialogFooter>
              <Button type="submit" disabled={createSecret.isPending}>
                {createSecret.isPending ? "Creating…" : "Create secret"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
