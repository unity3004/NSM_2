import { useState } from "react"
import { Link } from "react-router-dom"
import { AuthLayout } from "@/layouts/AuthLayout"
import { LoginForm } from "@/features/auth/LoginForm"
import { usePlatformStatus } from "@/features/setup/usePlatformStatus"
import { RouteLoading } from "@/components/RouteLoading"
import { KanzSplash } from "@/components/brand/KanzSplash"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"

// Gates the full KanzSplash intro to once per browser tab session — a
// hard reload of /login (or coming back here after logging out) re-mounts
// LoginPage, and without this it would replay the ~1.7s sequence every
// time, which is exactly what the brand brief says not to do ("do not
// make the startup animation play every time the user navigates").
// sessionStorage (not localStorage) is deliberate: a genuinely new tab —
// arguably a real "initial application loading" — sees it again.
const SPLASH_SEEN_KEY = "kanz-intro-seen"

// On success, useLogin's onSuccess calls authStore.setTokens, which makes
// useIsAuthenticated() true — PublicRoute (wrapping this page) reacts to
// that on its very next render and redirects to /dashboard. No imperative
// navigate() call needed here.
export function LoginPage() {
  const { data, isLoading } = usePlatformStatus()
  const [showSplash, setShowSplash] = useState(
    () => typeof window !== "undefined" && !window.sessionStorage.getItem(SPLASH_SEEN_KEY),
  )

  if (showSplash) {
    return (
      <KanzSplash
        onDone={() => {
          window.sessionStorage.setItem(SPLASH_SEEN_KEY, "1")
          setShowSplash(false)
        }}
      />
    )
  }

  if (isLoading) return <RouteLoading />

  // A fresh installation has no administrator to log in as at all — show
  // a way into setup instead of a login form nothing could ever satisfy.
  // Not called "Sign Up": this creates the platform's one initial
  // administrator, not a self-service account (see BootstrapForm).
  if (data && !data.initialized) {
    return (
      <AuthLayout>
        <Card className="shadow-lg shadow-black/20">
          <CardHeader>
            <CardTitle className="text-xl">No administrator yet</CardTitle>
            <CardDescription>
              This installation hasn't been set up yet. Create the initial administrator
              account to get started.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild className="h-10 w-full text-sm font-semibold tracking-wide uppercase">
              <Link to="/setup">Initialize your security platform</Link>
            </Button>
          </CardContent>
        </Card>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout>
      <LoginForm />
    </AuthLayout>
  )
}
