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
import { PasswordInput } from "@/components/PasswordInput"
import { useCreateUser } from "@/features/users/useCreateUser"
import { ApiError } from "@/lib/apiError"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { UserPlus } from "lucide-react"

const hasLower = /[a-z]/
const hasUpper = /[A-Z]/
const hasDigit = /\d/
const hasSymbol = /[^A-Za-z\d]/

function passwordPolicyIssues(password: string): string[] {
  const issues: string[] = []
  if (password.length < 12) issues.push("at least 12 characters")
  if (!hasLower.test(password)) issues.push("a lowercase letter")
  if (!hasUpper.test(password)) issues.push("an uppercase letter")
  if (!hasDigit.test(password)) issues.push("a number")
  if (!hasSymbol.test(password)) issues.push("a symbol")
  return issues
}

function friendlyCreateError(error: unknown): string {
  if (error instanceof ApiError && error.code === "CONFLICT") {
    return "An account with this email already exists."
  }
  return friendlyErrorMessage(error)
}

export function CreateUserDialog() {
  const [open, setOpen] = useState(false)
  const [username, setUsername] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [touched, setTouched] = useState(false)
  const createUser = useCreateUser()

  const policyIssues = passwordPolicyIssues(password)
  const usernameMissing = touched && username.trim() === ""
  const emailMissing = touched && email.trim() === ""
  const passwordInvalid = touched && policyIssues.length > 0

  function reset() {
    setUsername("")
    setEmail("")
    setPassword("")
    setTouched(false)
    createUser.reset()
  }

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (username.trim() === "" || email.trim() === "" || passwordPolicyIssues(password).length > 0) {
      return
    }
    createUser.mutate(
      { username, email, password },
      {
        onSuccess: () => {
          setOpen(false)
          reset()
        },
      },
    )
  }

  const fieldErrors = new Map<string, string>()
  if (createUser.error instanceof ApiError && createUser.error.details) {
    for (const detail of createUser.error.details) {
      fieldErrors.set(detail.field, detail.issue)
    }
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
          <UserPlus />
          Add user
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Add user</DialogTitle>
            <DialogDescription>
              Creates the account with the password below. Invitation-based onboarding, where
              the user sets their own password, is not yet implemented — see the roadmap.
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-4 py-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="new-user-name">Name</Label>
              <Input
                id="new-user-name"
                autoFocus
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                aria-invalid={usernameMissing || fieldErrors.has("username")}
              />
              {(usernameMissing || fieldErrors.has("username")) && (
                <p className="text-sm text-destructive">
                  {fieldErrors.get("username") ?? "Name is required."}
                </p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="new-user-email">Email</Label>
              <Input
                id="new-user-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                aria-invalid={emailMissing || fieldErrors.has("email")}
              />
              {(emailMissing || fieldErrors.has("email")) && (
                <p className="text-sm text-destructive">
                  {fieldErrors.get("email") ?? "Email is required."}
                </p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="new-user-password">Temporary password</Label>
              <PasswordInput
                id="new-user-password"
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                aria-invalid={passwordInvalid}
              />
              <p className="text-xs text-muted-foreground">
                At least 12 characters, with uppercase, lowercase, a number, and a symbol.
              </p>
              {passwordInvalid && (
                <p className="text-sm text-destructive">Password needs {policyIssues.join(", ")}.</p>
              )}
            </div>

            {createUser.isError && (
              <p role="alert" className="text-sm text-destructive">
                {friendlyCreateError(createUser.error)}
              </p>
            )}
          </div>

          <DialogFooter>
            <Button type="submit" disabled={createUser.isPending}>
              {createUser.isPending ? "Creating…" : "Create user"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
