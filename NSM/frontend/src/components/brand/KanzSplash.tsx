import { useEffect, useRef } from "react"
import { KanzMark } from "@/components/brand/KanzMark"

const TOTAL_DURATION_MS = 1700
// Matches the @media (prefers-reduced-motion: reduce) block in index.css,
// which collapses every animation to ~0 — there's nothing left to wait
// out, so reduced-motion visitors get straight through instead of sitting
// on a blank-feeling screen for the full duration.
const REDUCED_MOTION_DURATION_MS = 150

/**
 * The full one-time KANZ intro sequence: fragments appear and orbit, the
 * core illuminates, then the wordmark and tagline fade in. ~1.2–1.8s total
 * (index.css owns the actual keyframe timing — this component only knows
 * when the sequence is over, so it can hand off to `onDone`).
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
      <KanzMark size={72} variant="splash" />
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
