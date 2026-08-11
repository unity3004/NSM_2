import { useEffect, useState, type FormEvent } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { useUpdateSecret } from "@/features/secrets/useUpdateSecret"
import { useSecretFieldsEditor } from "@/features/secrets/useSecretFieldsEditor"
import { SecretFieldsEditor } from "@/features/secrets/SecretFieldsEditor"
import { ApiError } from "@/lib/apiError"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { toast } from "sonner"

/**
 * Updating always creates a new, immutable version — there is no code path
 * here that overwrites currentVersion's row. expectedVersion (sent as
 * If-Match by useUpdateSecret/secretsApi) is the optimistic-concurrency
 * guard: if someone else's update already landed since this sheet last
 * fetched the secret's metadata, the backend rejects this one with 409
 * VERSION_CONFLICT rather than silently layering on top of a change this
 * form never saw.
 *
 * initialData, when given, pre-fills the editable fields from a value the
 * caller *already* explicitly revealed this session (see
 * SecretDetailSheet's own doc comment) — this component never fetches
 * plaintext itself. Omitted, the form starts empty, and the submitted
 * `data` object still fully replaces the secret's value (PUT is not a
 * partial patch): a field left out here will not exist in the new version.
 */
export function UpdateSecretDialog({
  path,
  currentVersion,
  initialData,
  open,
  onOpenChange,
}: {
  path: string
  currentVersion: number
  initialData: Record<string, string> | null
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [touched, setTouched] = useState(false)
  const editor = useSecretFieldsEditor(initialData ?? undefined)
  const updateSecret = useUpdateSecret(path)

  // Re-seed the editor whenever the dialog opens (or the revealed data it
  // would seed from changes) rather than only on first mount, since this
  // component stays mounted across opens/closes inside SecretDetailSheet.
  useEffect(() => {
    if (open) {
      editor.reset(initialData ?? undefined)
      setTouched(false)
      updateSecret.reset()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  function friendlyUpdateError(error: unknown): string {
    if (error instanceof ApiError && error.isVersionConflict) {
      return "This secret was updated by someone else. Refresh before making changes."
    }
    return friendlyErrorMessage(error)
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (!editor.isValid) return
    updateSecret.mutate(
      { data: editor.payload, expectedVersion: currentVersion },
      {
        onSuccess: (updated) => {
          toast.success(`Secret "${path}" updated to version ${updated.version}.`)
          onOpenChange(false)
        },
      },
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Update secret</DialogTitle>
            <DialogDescription>
              <span className="font-mono">{path}</span> — this creates version {currentVersion + 1};
              version {currentVersion} remains unchanged and retrievable.
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-4 py-4">
            {!initialData && (
              <p className="text-xs text-muted-foreground">
                Starting from an empty form. Reveal the current value first if you want to edit
                specific fields instead of replacing all of them.
              </p>
            )}

            <div className="flex flex-col gap-2">
              <Label>Data</Label>
              <SecretFieldsEditor editor={editor} touched={touched} />
            </div>

            {updateSecret.isError && (
              <p role="alert" className="text-sm text-destructive">
                {friendlyUpdateError(updateSecret.error)}
              </p>
            )}
          </div>

          <DialogFooter>
            <Button type="submit" disabled={updateSecret.isPending}>
              {updateSecret.isPending ? "Updating…" : "Update secret"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
