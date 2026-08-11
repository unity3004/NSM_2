import { AuthLayout } from "@/layouts/AuthLayout"
import { LoginForm } from "@/features/auth/LoginForm"

// On success, useLogin's onSuccess calls authStore.setTokens, which makes
// useIsAuthenticated() true — PublicRoute (wrapping this page) reacts to
// that on its very next render and redirects to /dashboard. No imperative
// navigate() call needed here.
export function LoginPage() {
  return (
    <AuthLayout>
      <LoginForm />
    </AuthLayout>
  )
}
