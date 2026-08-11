import { useRef, useState, type FormEvent } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useLogin } from "@/features/auth/useLogin"
import { ApiError } from "@/lib/apiError"
import { friendlyErrorMessage } from "@/lib/errorMessage"

/**
 * Friendly, deliberately non-enumerating copy — preserves the backend's own
 * anti-enumeration design (INVALID_CREDENTIALS never distinguishes "no such
 * user" from "wrong password"; see AuthService.Login). This mapping must
 * not "help" by being more specific than the backend already chose to be.
 * Only the login-specific case (wrong credentials) needs copy of its own;
 * everything else (locked, rate-limited, validation, network, 5xx) falls
 * through to the app-wide mapping in lib/errorMessage.ts so this form
 * doesn't maintain its own duplicate copy of generic error text.
 */
function friendlyLoginError(error: unknown): string {
  if (error instanceof ApiError && error.isInvalidCredentials) {
    return "Incorrect email or password."
  }
  return friendlyErrorMessage(error)
}

export function LoginForm() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const login = useLogin()
  // A ref, not login.isPending: isPending is React state, which only
  // updates on the next render. Two submits dispatched in the same tick
  // (e.g. a double-click, or Enter auto-repeating) both run handleSubmit
  // before React ever re-renders, so both would read the same stale
  // `false` and both call mutate() — confirmed by a real duplicate-submit
  // test against the live backend before this ref was added. A ref
  // mutates synchronously and is visible to the very next call in the
  // same tick, which is what actually closes the gap the disabled button
  // alone cannot.
  const submitting = useRef(false)

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (submitting.current) return
    submitting.current = true
    login.mutate(
      { email, password },
      { onSettled: () => { submitting.current = false } },
    )
  }

  const fieldErrors = new Map<string, string>()
  if (login.error instanceof ApiError && login.error.details) {
    for (const detail of login.error.details) {
      fieldErrors.set(detail.field, detail.issue)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xl">Sign in</CardTitle>
        <CardDescription>Enter your credentials to access your account.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-5">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
              autoFocus
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              aria-invalid={fieldErrors.has("email")}
              required
            />
            {fieldErrors.has("email") && (
              <p className="text-sm text-destructive">{fieldErrors.get("email")}</p>
            )}
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              aria-invalid={fieldErrors.has("password")}
              required
            />
            {fieldErrors.has("password") && (
              <p className="text-sm text-destructive">{fieldErrors.get("password")}</p>
            )}
          </div>

          {login.isError && (
            <p role="alert" className="text-sm text-destructive">
              {friendlyLoginError(login.error)}
            </p>
          )}

          <Button type="submit" disabled={login.isPending} className="mt-1">
            {login.isPending ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
