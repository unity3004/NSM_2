import { useState, type FormEvent } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useLogin } from "@/features/auth/useLogin"
import { ApiError } from "@/lib/apiError"

/**
 * Friendly, deliberately non-enumerating copy — preserves the backend's own
 * anti-enumeration design (INVALID_CREDENTIALS never distinguishes "no such
 * user" from "wrong password"; see AuthService.Login). This mapping must
 * not "help" by being more specific than the backend already chose to be.
 */
function friendlyLoginError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.isInvalidCredentials) return "Incorrect email or password."
    if (error.isAccountLocked) {
      return "This account is temporarily locked after repeated failed attempts. Try again later."
    }
    if (error.isRateLimited) return "Too many attempts. Please wait a moment and try again."
    if (error.code === "VALIDATION_ERROR") return "Please check the highlighted fields."
    if (error.code === "NETWORK_ERROR") return error.message
  }
  return "Something went wrong. Please try again."
}

export function LoginForm() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const login = useLogin()

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    login.mutate({ email, password })
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
