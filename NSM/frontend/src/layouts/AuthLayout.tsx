import type { ReactNode } from "react"
import { Brand } from "@/components/Brand"

/**
 * Two-column split on desktop — identity/security messaging on the left,
 * the actual auth card (children) on the right — collapsing to a single
 * stacked column below the lg breakpoint. The left panel is presentational
 * only (no interactive content), so hiding it below lg costs nothing
 * functional; the primary, desktop enterprise-console experience keeps its
 * full identity panel.
 */
export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-svh flex-col bg-background lg:flex-row">
      <div className="hidden flex-col justify-between border-r border-border bg-card/40 px-12 py-16 lg:flex lg:w-[45%] xl:w-1/2">
        <Brand size="lg" />

        <div className="max-w-md">
          <h1 className="text-3xl leading-tight font-semibold tracking-tight text-balance text-foreground">
            Enterprise Secrets Management Platform
          </h1>
          <p className="mt-4 text-base text-pretty text-muted-foreground">
            Secure your organization's most sensitive credentials, with full
            visibility into who accessed what, and when.
          </p>
          <p className="mt-6 text-xs font-medium tracking-[0.2em] text-primary uppercase">
            Secure&nbsp;&nbsp;•&nbsp;&nbsp;Audited&nbsp;&nbsp;•&nbsp;&nbsp;Controlled
          </p>
        </div>

        <p className="text-xs text-muted-foreground">
          © {new Date().getFullYear()} Vaultis. All rights reserved.
        </p>
      </div>

      <div className="flex flex-1 flex-col items-center justify-center gap-8 px-4 py-12 sm:px-6">
        <Brand size="sm" className="lg:hidden" />
        <div className="w-full max-w-sm">{children}</div>
      </div>
    </div>
  )
}
