import { useRef, useState, type FormEvent } from "react"
import { useNavigate } from "react-router-dom"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { PasswordInput } from "@/components/PasswordInput"
import { useBootstrap } from "@/features/setup/useBootstrap"
import { ApiError } from "@/lib/apiError"
import { friendlyErrorMessage } from "@/lib/errorMessage"

// Mirrors the backend's real policy exactly (dto.isPasswordComplexEnough)
// — this is client-side feedback only, never the source of truth; the
// backend re-validates the identical rule independently on submit.
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

function friendlyBootstrapError(error: unknown): string {
  if (error instanceof ApiError && error.code === "CONFLICT") {
    return "This platform has already been initialized. Redirecting to sign in…"
  }
  return friendlyErrorMessage(error)
}

export function BootstrapForm() {
  const navigate = useNavigate()
  const [username, setUsername] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [touched, setTouched] = useState(false)
  const bootstrap = useBootstrap()
  // Same synchronous-ref double-submit guard LoginForm uses — see that
  // file's doc comment for why login.isPending (React state) alone can't
  // close the same-tick double-submit gap.
  const submitting = useRef(false)

  const policyIssues = passwordPolicyIssues(password)
  const usernameMissing = touched && username.trim() === ""
  const emailMissing = touched && email.trim() === ""
  const passwordInvalid = touched && policyIssues.length > 0
  const confirmMismatch = touched && password !== confirmPassword

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (
      username.trim() === "" ||
      email.trim() === "" ||
      passwordPolicyIssues(password).length > 0 ||
      password !== confirmPassword
    ) {
      return
    }
    if (submitting.current) return
    submitting.current = true
    bootstrap.mutate(
      { username, email, password },
      {
        onSettled: () => {
          submitting.current = false
        },
        onSuccess: () => {
          navigate("/login", { replace: true })
        },
        onError: (error) => {
          if (error instanceof ApiError && error.code === "CONFLICT") {
            setTimeout(() => navigate("/login", { replace: true }), 1800)
          }
        },
      },
    )
  }

  const fieldErrors = new Map<string, string>()
  if (bootstrap.error instanceof ApiError && bootstrap.error.details) {
    for (const detail of bootstrap.error.details) {
      fieldErrors.set(detail.field, detail.issue)
    }
  }

  const usernameError = usernameMissing ? "Administrator name is required." : fieldErrors.get("username")
  const emailError = emailMissing ? "Email is required." : fieldErrors.get("email")
  const passwordError = passwordInvalid
    ? `Password needs ${policyIssues.join(", ")}.`
    : fieldErrors.get("password")
  const confirmError = confirmMismatch ? "Passwords do not match." : undefined

  return (
    <Card className="shadow-lg shadow-black/20">
      <CardHeader>
        <CardTitle className="text-xl">Initialize your security platform</CardTitle>
        <CardDescription>
          This installation has no administrator yet. Create the initial administrator account
          to continue.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-5">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="username">Administrator name</Label>
            <Input
              id="username"
              name="username"
              type="text"
              autoComplete="name"
              autoFocus
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              aria-invalid={!!usernameError}
              aria-describedby={usernameError ? "username-error" : undefined}
            />
            {usernameError && (
              <p id="username-error" className="text-sm text-destructive">
                {usernameError}
              </p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              aria-invalid={!!emailError}
              aria-describedby={emailError ? "email-error" : undefined}
            />
            {emailError && (
              <p id="email-error" className="text-sm text-destructive">
                {emailError}
              </p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="password">Password</Label>
            <PasswordInput
              id="password"
              name="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              aria-invalid={!!passwordError}
              aria-describedby="password-requirements password-error"
            />
            <p id="password-requirements" className="text-xs text-muted-foreground">
              At least 12 characters, with uppercase, lowercase, a number, and a symbol.
            </p>
            {passwordError && (
              <p id="password-error" className="text-sm text-destructive">
                {passwordError}
              </p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="confirm-password">Confirm password</Label>
            <PasswordInput
              id="confirm-password"
              name="confirm-password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              aria-invalid={!!confirmError}
              aria-describedby={confirmError ? "confirm-password-error" : undefined}
            />
            {confirmError && (
              <p id="confirm-password-error" className="text-sm text-destructive">
                {confirmError}
              </p>
            )}
          </div>

          {bootstrap.isError && (
            <p role="alert" className="text-sm text-destructive">
              {friendlyBootstrapError(bootstrap.error)}
            </p>
          )}

          <Button
            type="submit"
            disabled={bootstrap.isPending}
            className="mt-1 h-10 text-sm font-semibold tracking-wide uppercase"
          >
            {bootstrap.isPending ? "Initializing…" : "Create administrator account"}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
