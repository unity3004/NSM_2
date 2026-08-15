import type { CSSProperties } from "react"

// A handful of tiny, slow-drifting dots — background texture only, never
// more than PARTICLES.length elements, well short of anything that could
// read as "excessive particles." Positions/timings are fixed, not
// randomized on every render, so this never causes a layout shift or a
// different look on each mount.
const PARTICLES = [
  { left: "8%", top: "18%", duration: "10s", delay: "0s", opacity: 0.3 },
  { left: "22%", top: "62%", duration: "13s", delay: "-4s", opacity: 0.22 },
  { left: "38%", top: "30%", duration: "11s", delay: "-7s", opacity: 0.28 },
  { left: "68%", top: "70%", duration: "14s", delay: "-2s", opacity: 0.2 },
  { left: "82%", top: "24%", duration: "12s", delay: "-9s", opacity: 0.3 },
] as const

/** The login page's "extremely subtle atmospheric particles" — see
 * AuthLayout.tsx's own use of .kanz-auth-bg for the rest of the
 * background depth (radial glow + faint grid). Kept separate from that
 * CSS-only background so these can be prefers-reduced-motion-aware
 * without touching AuthLayout's markup. */
export function AtmosphereParticles() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
      {PARTICLES.map((p, i) => (
        <span
          key={i}
          className="kanz-atmosphere-particle absolute size-1 rounded-full bg-kanz-primary-glow"
          style={
            {
              left: p.left,
              top: p.top,
              "--kanz-particle-duration": p.duration,
              "--kanz-particle-delay": p.delay,
              "--kanz-particle-opacity": p.opacity,
            } as CSSProperties
          }
        />
      ))}
    </div>
  )
}
