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
import { KeyRound } from "lucide-react"
import { toast } from "sonner"

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

export function CreateSecretDialog() {
  const [open, setOpen] = useState(false)
  const [path, setPath] = useState("")
  const [touched, setTouched] = useState(false)
  const editor = useSecretFieldsEditor()
  const createSecret = useCreateSecret()

  const pathError = touched ? validatePath(path) : null

  function reset() {
    setPath("")
    editor.reset()
    setTouched(false)
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
          setOpen(false)
          reset()
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
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Create secret</DialogTitle>
            <DialogDescription>
              The entire set of fields below is encrypted as one unit. Values are hidden by
              default — use the show/hide toggle to verify what you're entering.
            </DialogDescription>
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
      </DialogContent>
    </Dialog>
  )
}
