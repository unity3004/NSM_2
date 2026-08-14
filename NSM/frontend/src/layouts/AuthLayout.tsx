import type { ReactNode } from "react"
import { KanzLogo } from "@/components/brand/KanzLogo"
import { SecurityCoreField } from "@/features/auth/SecurityCoreField"
import { AtmosphereParticles } from "@/features/auth/AtmosphereParticles"
import { cn } from "@/lib/utils"

/**
 * Two-zone responsive KANZ security gateway — ONE unified environment,
 * not two visually separate panels: there is no dividing border between
 * left and right (removed deliberately; see .kanz-auth-bg below, which
 * spans the full outer wrapper so the background grid/glow read as
 * continuous across the whole viewport).
 *
 * Structure:
 *  - Outer, always-full-viewport background layer (.kanz-auth-bg + the
 *    grid it paints, plus AtmosphereParticles) — this is what keeps
 *    ultrawide screens from feeling like an empty void around a tiny
 *    card, without the left/right split being a hard architectural line.
 *  - A centered `max-w-[1600px]` content row inside it, so the two zones
 *    never stretch to an absurd width on a 3440px display.
 *  - Left (~45%, lg and up): the brand/security composition — KanzLogo
 *    (the one real logo; SecurityCoreField is an ambient interactive
 *    backdrop, never a second logo) — is centered *within this column*
 *    (flex items-center justify-center on a full-height wrapper), not
 *    relative to the browser viewport, so it stays balanced regardless
 *    of how wide the overall page is.
 *  - Right (flex-1, form capped around 440px): the actual auth UI
 *    (children) — LoginForm's own logic is completely untouched.
 */
export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="kanz-auth-bg kanz-auth-shell relative flex min-h-svh flex-col">
      <AtmosphereParticles />

      <div className="relative z-10 mx-auto flex w-full max-w-[1600px] flex-1 flex-col lg:flex-row">
        {/* Full left brand panel — lg (desktop) and up. No border here:
            the divider that used to separate this from the login panel
            was removed on purpose (see this file's own doc comment). The
            copyright line used to live at the bottom of *this* column
            (px-12 pb-8, inside a `lg:flex`-only block) — that's what made
            it read as floating mid-composition and invisible below `lg`;
            it's now a real page-level <footer> below, a sibling of this
            whole row rather than scoped to the left column. */}
        <div className="hidden flex-1 flex-col items-center justify-center px-12 py-16 lg:flex lg:w-[45%]">
          <BrandComposition logoSize={160} fieldSize={320} />
        </div>

        {/* Compact tablet header (sm–lg): a scaled-down version of the
            same composition — not hidden, per the brief's own distinction
            between "tablet: scale down" and "mobile: simplify/hide". */}
        <div className="hidden flex-col items-center gap-4 px-4 pt-10 sm:flex lg:hidden">
          <BrandComposition logoSize={76} fieldSize={180} compact />
        </div>

        {/* Mobile header (below sm): logo + wordmark only, KANZ still the
            dominant element — the login form stays the eventual priority,
            but the brief is explicit that KANZ must be recognized first,
            at every tier. */}
        <div className="flex flex-col items-center gap-1.5 px-4 pt-10 sm:hidden">
          <KanzLogo variant="large" size={52} />
          <h1 className="text-2xl font-extrabold tracking-tight text-foreground">KANZ</h1>
        </div>

        {/* Login panel. */}
        <div className="flex flex-1 flex-col items-center justify-center gap-8 px-4 py-10 sm:px-6">
          <div className="w-full max-w-[440px]">{children}</div>
        </div>
      </div>

      {/* True page footer — a sibling of the content row above, not
          nested inside the left column. .kanz-auth-shell is already a
          `min-h-svh flex flex-col` page shell (see its own class), so this
          simply sits after the `flex-1` content row: the row grows to
          fill available height, this stays pinned at the bottom without
          `position: absolute`, and on a short viewport the row still
          scrolls normally rather than this overlapping anything. Same
          `max-w-[1600px]` + `mx-auto` container as the content row above,
          so the copyright aligns with the page's actual content boundary
          instead of centering under the left visualization. */}
      <footer className="relative z-10 shrink-0">
        <div className="mx-auto w-full max-w-[1600px] px-4 py-6 sm:px-6 lg:px-12">
          <p className="text-xs text-muted-foreground">
            © {new Date().getFullYear()} KANZ. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  )
}

/**
 * Security Core → animated logo → KANZ (the hero) → tagline →
 * supporting text, centered as one group. Deliberately not <Brand>,
 * which lays the mark and wordmark out side-by-side for chrome contexts
 * (sidebar, topbar) — this composition wants KANZ itself to be the
 * dominant element on the page, with the symbol feeding visually into it,
 * still built from the same KanzLogo component, never a second logo
 * implementation and never a redesign of SecurityCoreField's own
 * interactions (untouched — see that file).
 *
 * "KANZ" carries the page's one <h1>: it is the actual primary heading
 * now, not the tagline underneath it — matching the visual hierarchy
 * (brand > product story > tagline > supporting text > action) with the
 * semantic one, which also happens to be what a screen reader user
 * should hear first on this page.
 */
function BrandComposition({
  logoSize,
  fieldSize,
  compact = false,
}: {
  logoSize: number
  fieldSize: number
  compact?: boolean
}) {
  return (
    <div className="kanz-security-visual flex flex-col items-center">
      <div className="relative flex items-center justify-center" style={{ width: fieldSize, height: fieldSize }}>
        {/* SecurityCoreField must come before .kanz-core-response in the
            DOM — the sibling selector driving the core's hover reaction
            (index.css) only looks at *later* siblings. */}
        <SecurityCoreField size={fieldSize} />
        <div className="kanz-core-response relative">
          <KanzLogo variant="large" size={logoSize} />
        </div>
      </div>

      {/* A thin fading cyan thread from the core down into the wordmark —
          "the security core generates the KANZ identity," kept to a
          single subtle line rather than any kind of transformation. */}
      <div className="h-6 w-px bg-gradient-to-b from-kanz-primary/50 to-transparent" aria-hidden="true" />

      <h1
        className={cn(
          "font-extrabold tracking-tight text-foreground",
          compact ? "text-3xl" : "text-6xl xl:text-7xl",
        )}
        style={{ textShadow: "0 0 28px color-mix(in oklab, var(--kanz-primary-glow) 30%, transparent)" }}
      >
        KANZ
      </h1>

      <p
        className={cn(
          "mt-4 text-center leading-snug font-semibold text-balance text-foreground",
          compact ? "text-sm" : "text-lg",
        )}
      >
        Secure Every <span className="text-kanz-primary">Secret</span>.
        <br />
        Control Every <span className="text-kanz-primary">Identity</span>.
      </p>

      {!compact && (
        <p className="mt-3 max-w-sm text-center text-sm font-medium text-pretty text-muted-foreground">
          Enterprise Secrets &amp; Identity Security Platform
        </p>
      )}
    </div>
  )
}
