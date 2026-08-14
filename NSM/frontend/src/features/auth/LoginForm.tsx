import { useRef, useState, type FormEvent } from "react"
import { AlertTriangle, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { PasswordInput } from "@/components/PasswordInput"
import { ConnectionSecurityIndicator } from "@/components/ConnectionSecurityIndicator"
import { useLogin } from "@/features/auth/useLogin"
import { ApiError } from "@/lib/apiError"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { cn } from "@/lib/utils"

/**
 * Friendly, deliberately non-enumerating copy — preserves the backend's own
 * anti-enumeration design (INVALID_CREDENTIALS never distinguishes "no such
 * user" from "wrong password"; see AuthService.Login). This mapping must
 * not "help" by being more specific than the backend already chose to be.
 * A few cases here intentionally use login-specific wording that differs
 * from lib/errorMessage.ts's generic copy (e.g. "login attempts" instead
 * of "attempts") — everything else falls through to that shared mapping
 * so this form doesn't maintain a full duplicate of it.
 */
function friendlyLoginError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.isInvalidCredentials) return "Invalid email or password."
    if (error.code === "ACCOUNT_DISABLED") {
      return "Your account has been disabled. Contact your administrator."
    }
    if (error.isRateLimited) return "Too many login attempts. Please try again later."
    if (error.code === "NETWORK_ERROR") return "Unable to connect to the authentication service."
  }
  return friendlyErrorMessage(error)
}

export function LoginForm() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  // Client-side "is this field empty" feedback — separate from the
  // backend's own field errors below, and checked before a request is
  // even sent, so an empty submit never costs a network round trip just
  // to learn what the browser could already tell us.
  const [touched, setTouched] = useState(false)
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

  const emailMissing = touched && email.trim() === ""
  const passwordMissing = touched && password === ""

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setTouched(true)
    if (email.trim() === "" || password === "") return
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

  const emailError = emailMissing ? "Email is required." : fieldErrors.get("email")
  const passwordError = passwordMissing ? "Password is required." : fieldErrors.get("password")

  return (
    <div className="flex flex-col gap-4">
      <Card className="gap-6 border border-border shadow-xl shadow-black/30">
        <CardHeader className="gap-1.5">
          <CardTitle className="text-xl">Welcome back</CardTitle>
          <p className="text-sm font-medium text-kanz-primary">Sign in to KANZ</p>
          <CardDescription>Secure access to your secrets and identities.</CardDescription>
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
                className="h-10"
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
                autoComplete="current-password"
                className="h-10"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                aria-invalid={!!passwordError}
                aria-describedby={passwordError ? "password-error" : undefined}
              />
              {passwordError && (
                <p id="password-error" className="text-sm text-destructive">
                  {passwordError}
                </p>
              )}
            </div>

            {login.isError && (
              <p
                role="alert"
                className="flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                {friendlyLoginError(login.error)}
              </p>
            )}

            <Button
              type="submit"
              disabled={login.isPending}
              className={cn(
                "mt-1 h-10 text-sm font-semibold tracking-wide uppercase",
                "hover:bg-primary/90 transition-colors",
              )}
            >
              {login.isPending && <Loader2 className="size-4 animate-spin" aria-hidden="true" />}
              {login.isPending ? "Authenticating…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <ConnectionSecurityIndicator />
    </div>
  )
}
