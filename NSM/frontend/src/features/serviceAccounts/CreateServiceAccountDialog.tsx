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
import { useCreateServiceAccount } from "@/features/serviceAccounts/useCreateServiceAccount"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { ApiError } from "@/lib/apiError"
import { Bot } from "lucide-react"
import { toast } from "sonner"

function friendlyCreateError(error: unknown): string {
  if (error instanceof ApiError && error.code === "CONFLICT") {
    return "A service account with this name already exists in this organization."
  }
  return friendlyErrorMessage(error)
}

export function CreateServiceAccountDialog() {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [touched, setTouched] = useState(false)
  const createServiceAccount = useCreateServiceAccount()

  function reset() {
    setName("")
    setDescription("")
    setTouched(false)
    createServiceAccount.reset()
  }

  const nameError = touched && name.trim() === "" ? "Name is required." : null
  const isValid = name.trim() !== ""

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (!isValid) return

    createServiceAccount.mutate(
      { name: name.trim(), description: description.trim() || undefined },
      {
        onSuccess: (created) => {
          toast.success(`Service account "${created.name}" created.`)
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
          <Bot />
          New service account
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Create service account</DialogTitle>
            <DialogDescription>
              A service account is a non-human identity for an application or workload. Grant it a
              role and issue it a credential afterward — it authenticates separately from human login.
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-4 py-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="sa-name">Name</Label>
              <Input
                id="sa-name"
                autoFocus
                placeholder="payment-service"
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

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="sa-description">Description (optional)</Label>
              <Input
                id="sa-description"
                placeholder="Payments integration — reads prod/payment/* only"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </div>

            {createServiceAccount.isError && (
              <p role="alert" className="text-sm text-destructive">
                {friendlyCreateError(createServiceAccount.error)}
              </p>
            )}
          </div>

          <DialogFooter>
            <Button type="submit" disabled={createServiceAccount.isPending}>
              {createServiceAccount.isPending ? "Creating…" : "Create service account"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
