import { useState, type FormEvent } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useCreateCredential } from "@/features/serviceAccounts/useServiceAccountMutations"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { KeyRound, TriangleAlert, Copy, Check } from "lucide-react"
import { toast } from "sonner"

/**
 * Issues a new credential and — once, immediately after creation — shows
 * the raw secret with an explicit "shown only once" warning, matching
 * this sprint's own explicit CREDENTIAL SECURITY requirement. Closing
 * this dialog (or navigating away) is the point of no return: the secret
 * was never persisted anywhere the frontend can read it back from — only
 * ApiKeyCreatedResponse.secret, present in this one HTTP response body,
 * ever carried it. Re-opening this dialog for the same credential is not
 * possible; issuing a new one (or rotating) is the only recovery from a
 * lost secret.
 */
export function CreateCredentialDialog({
  serviceAccountId,
  open,
  onOpenChange,
}: {
  serviceAccountId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [name, setName] = useState("")
  const [touched, setTouched] = useState(false)
  const [copied, setCopied] = useState(false)
  const createCredential = useCreateCredential(serviceAccountId)

  function reset() {
    setName("")
    setTouched(false)
    setCopied(false)
    createCredential.reset()
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (name.trim() === "") return
    createCredential.mutate({ name: name.trim() })
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

  const created = createCredential.data
  const nameError = touched && name.trim() === "" ? "Name is required." : null

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next)
        if (!next) reset()
      }}
    >
      <DialogContent className="sm:max-w-md">
        {!created ? (
          <form onSubmit={handleSubmit}>
            <DialogHeader>
              <DialogTitle>Issue a new credential</DialogTitle>
              <DialogDescription>
                The credential secret will only be shown once, immediately after creation. Store it in
                a secrets manager or environment variable — it cannot be retrieved again.
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-col gap-4 py-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="cred-name">Name</Label>
                <Input
                  id="cred-name"
                  autoFocus
                  placeholder="ci-integration-tests"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  aria-invalid={!!nameError}
                />
                {nameError && (
                  <p role="alert" className="text-sm text-destructive">
                    {nameError}
                  </p>
                )}
              </div>

              {createCredential.isError && (
                <p role="alert" className="text-sm text-destructive">
                  {friendlyErrorMessage(createCredential.error)}
                </p>
              )}
            </div>

            <DialogFooter>
              <Button type="submit" disabled={createCredential.isPending}>
                <KeyRound />
                {createCredential.isPending ? "Issuing…" : "Issue credential"}
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Credential issued</DialogTitle>
              <DialogDescription>
                Copy this secret now. It will never be shown again — this dialog is the only place it
                ever appears.
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-col gap-4 py-4">
              <div className="flex items-start gap-3 rounded-lg border border-destructive/50 bg-destructive/10 p-3">
                <TriangleAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
                <div className="flex flex-col gap-1">
                  <p className="text-sm font-medium text-destructive">
                    The credential secret will only be shown once.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    Store it now. Neither this page nor the backend can display it again — if it's
                    lost, revoke this credential and issue a new one.
                  </p>
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <Label>Secret</Label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 overflow-x-auto rounded-md border bg-muted px-2 py-1.5 text-xs">
                    {created.secret}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    aria-label="Copy secret to clipboard"
                    onClick={() => void handleCopy(created.secret)}
                  >
                    {copied ? <Check className="text-green-600" /> : <Copy />}
                  </Button>
                </div>
              </div>
            </div>

            <DialogFooter>
              <Button
                onClick={() => {
                  onOpenChange(false)
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
