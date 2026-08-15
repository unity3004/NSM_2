import { useEffect, useRef } from "react"
import { KanzLogo } from "@/components/brand/KanzLogo"

const TOTAL_DURATION_MS = 1700
// Matches the @media (prefers-reduced-motion: reduce) block in index.css,
// which collapses every animation to ~0 — there's nothing left to wait
// out, so reduced-motion visitors get straight through instead of sitting
// on a blank-feeling screen for the full duration.
const REDUCED_MOTION_DURATION_MS = 150

/**
 * The KANZ intro screen: the large, continuously-alive KanzLogo mark plus
 * the wordmark and tagline fading up shortly after mount. Unlike the
 * mark's own motion (which never starts or stops — see KanzLogo's doc
 * comment), this *screen* is still a one-time beat: it hands off to
 * `onDone` after ~1.7s (index.css owns the wordmark/tagline fade timing)
 * so LoginPage can move on to the real login form.
 *
 * Deliberately NOT mounted by RouteLoading (used on every guarded route
 * transition, including a plain page reload) — that would replay this on
 * far more than "initial application loading." The one call site is
 * LoginPage's own first-load branch, itself gated to once per browser
 * session — see that file for the sessionStorage check.
 */
export function KanzSplash({ onDone, tagline = true }: { onDone: () => void; tagline?: boolean }) {
  const onDoneRef = useRef(onDone)
  onDoneRef.current = onDone

  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches
    const timer = window.setTimeout(
      () => onDoneRef.current(),
      reduced ? REDUCED_MOTION_DURATION_MS : TOTAL_DURATION_MS,
    )
    return () => window.clearTimeout(timer)
  }, [])

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-kanz-bg">
      <KanzLogo variant="large" />
      <div className="flex flex-col items-center gap-2">
        <span className="kanz-splash-wordmark text-2xl font-semibold tracking-tight text-kanz-text">
          KANZ
        </span>
        {tagline && (
          <span className="kanz-splash-tagline text-xs font-medium tracking-[0.15em] text-kanz-text-muted uppercase">
            Secure Every Secret. Control Every Identity.
          </span>
        )}
      </div>
    </div>
  )
}
