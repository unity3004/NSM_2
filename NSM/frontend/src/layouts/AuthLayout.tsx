import type { ReactNode } from "react"
import { ShieldCheck } from "lucide-react"

/** Centered card shell, no nav chrome — deliberately minimal, no
 * distractions from the one task this page has. */
export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-8 bg-background px-4">
      <div className="flex items-center gap-2 text-foreground">
        <ShieldCheck className="size-6 text-primary" strokeWidth={1.75} />
        <span className="text-lg font-semibold tracking-tight">Vaultis</span>
      </div>
      <div className="w-full max-w-sm">{children}</div>
    </div>
  )
}
