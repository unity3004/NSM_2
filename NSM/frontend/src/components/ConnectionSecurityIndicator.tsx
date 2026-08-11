import { Lock, ShieldAlert } from "lucide-react"

// Reflects the page's *actual* transport, checked at render time — never a
// hardcoded "secured" claim. This app is served over plain HTTP in local
// development (see vite.config.ts), and a login page is exactly the wrong
// place to lie about that: an operator glancing at this while running the
// dev server must see the truth, not a copy-pasted enterprise-SaaS badge.
export function ConnectionSecurityIndicator() {
  const isSecure = window.location.protocol === "https:"

  if (isSecure) {
    return (
      <p className="flex items-center justify-center gap-1.5 text-xs text-muted-foreground">
        <Lock className="size-3.5" strokeWidth={2} aria-hidden="true" />
        Your connection is secured
      </p>
    )
  }

  return (
    <p className="flex items-center justify-center gap-1.5 text-xs text-muted-foreground">
      <ShieldAlert className="size-3.5" strokeWidth={2} aria-hidden="true" />
      Development environment — connection is not encrypted
    </p>
  )
}
