import { useId } from "react"
import { cn } from "@/lib/utils"

/**
 * The KANZ mark: a "Living Security Core" — a fluid core and energy-field
 * ring, continuously and seamlessly morphing, with a small number of
 * orbiting particles that occasionally merge back into the core. Replaces
 * the earlier four-fragments-around-a-diamond KanzMark design, which this
 * component's own animation rules deliberately avoid recreating (no
 * discrete shapes orbiting a static core — see the "avoid" list this
 * redesign brief called out by name).
 *
 * Every bit of motion here is plain CSS (`transform`, `opacity`, and, for
 * the ring only, the SVG geometry attributes `rx`/`ry`) driven by
 * `@keyframes` in index.css — there is no JS animation loop, no
 * `requestAnimationFrame`, and no per-frame React re-render, so there is
 * nothing for this component to clean up on unmount. `animation-delay`
 * uses negative values (see index.css) so every instance renders already
 * mid-cycle on its very first frame — there is no visible "start" to the
 * loop, only continuous motion, matching this brief's core requirement.
 *
 * `prefers-reduced-motion: reduce` collapses every animation to its
 * resting frame (index.css, one shared rule) — that resting frame is
 * hand-picked to already look like a complete, premium mark on its own,
 * so reduced-motion users see a static version of the *same* identity,
 * never a degraded one.
 */
interface KanzLogoProps {
  variant?: "sidebar" | "large" | "static"
  size?: number
  className?: string
}

const VARIANT_DEFAULT_SIZE: Record<NonNullable<KanzLogoProps["variant"]>, number> = {
  sidebar: 26,
  large: 72,
  static: 40,
}

// Large gets one extra particle and a stronger outer glow ("may use more
// particles, stronger glow" — sidebar gets the reduced-particle,
// reduced-glow treatment the brief asks for instead).
const PARTICLE_COUNT: Record<NonNullable<KanzLogoProps["variant"]>, number> = {
  sidebar: 2,
  large: 3,
  static: 0,
}

// Starting points ~14px out from center (24, 24), spread across distinct
// angles so the (small) particle count never starts visually bunched —
// each one's own keyframe animation (index.css) takes over from here.
const PARTICLE_START = [
  { cx: 38, cy: 24 },
  { cx: 15, cy: 35 },
  { cx: 19, cy: 11 },
] as const

export function KanzLogo({ variant = "static", size, className }: KanzLogoProps) {
  const resolvedSize = size ?? VARIANT_DEFAULT_SIZE[variant]
  const animated = variant !== "static"
  const particleCount = PARTICLE_COUNT[variant]

  // AuthLayout mounts two Brand/KanzLogo instances at once (a desktop and
  // a CSS-hidden mobile-fallback variant — see that file), so <defs> ids
  // must be unique per instance, not the literal strings a single-copy
  // SVG could get away with: two <radialGradient id="kanz-core-grad">
  // elements in one document is invalid, and url(#kanz-core-grad) would
  // resolve to whichever came first, silently breaking the other.
  const uid = useId()
  const coreGradId = `kanz-core-grad-${uid}`
  const ringGradId = `kanz-ring-grad-${uid}`
  const gooId = `kanz-goo-${uid}`

  return (
    <svg
      width={resolvedSize}
      height={resolvedSize}
      viewBox="0 0 48 48"
      fill="none"
      role="img"
      aria-label="KANZ"
      className={cn("kanz-logo", variant === "large" && "kanz-logo-large", className)}
    >
      <defs>
        <radialGradient id={coreGradId} cx="50%" cy="50%" r="60%">
          <stop offset="0%" stopColor="var(--kanz-primary-glow)" />
          <stop offset="55%" stopColor="var(--kanz-primary)" />
          <stop offset="100%" stopColor="var(--kanz-secondary)" />
        </radialGradient>
        <linearGradient id={ringGradId} x1="8" y1="8" x2="40" y2="40" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="var(--kanz-primary-glow)" />
          <stop offset="100%" stopColor="var(--kanz-secondary)" />
        </linearGradient>
        {/* The classic "gooey" filter: blur everything together, then a
            steep alpha matrix re-sharpens the edges — two independent
            shapes (core + diamond) read as one continuously fusing fluid
            form instead of two overlapping outlines. */}
        <filter id={gooId} x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="1.6" result="blur" />
          <feColorMatrix in="blur" mode="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 22 -10" result="goo" />
          <feComposite in="SourceGraphic" in2="goo" operator="atop" />
        </filter>
      </defs>

      {/* Layer 2 — fluid ring: two independently deforming, independently
          rotating ellipses standing in for a single "energy field" ring —
          never a uniform, static circle. */}
      <g stroke={`url(#${ringGradId})`} fill="none">
        <ellipse
          className={cn(animated && "kanz-ring-a")}
          cx="24"
          cy="24"
          rx="15"
          ry="13.5"
          strokeWidth="1.4"
          opacity="0.85"
        />
        <ellipse
          className={cn(animated && "kanz-ring-b")}
          cx="24"
          cy="24"
          rx="12.5"
          ry="14.5"
          strokeWidth="1"
          opacity="0.45"
        />
      </g>

      {/* Layer 1 — central core: a circle and a rotated rounded-square
          cross-fade under the goo filter, which is what actually produces
          the "circle → rounded diamond → abstract polygon → circle"
          morph — never a single path with its `d` attribute animated
          (unreliable across browsers), and never an abrupt shape swap. */}
      <g filter={`url(#${gooId})`}>
        <circle
          className={cn(animated && "kanz-core-a")}
          cx="24"
          cy="24"
          r="6.5"
          fill={`url(#${coreGradId})`}
        />
        <rect
          className={cn(animated && "kanz-core-b")}
          x="17.5"
          y="17.5"
          width="13"
          height="13"
          rx="5"
          fill={`url(#${coreGradId})`}
          opacity="0.55"
          transform="rotate(45 24 24)"
        />
      </g>

      {/* Layer 3 — particles: a small, varying number of tiny dots. Each
          starts at a fixed off-center point (cx/cy below) and animates a
          single `transform: rotate(...) scale(...)` anchored at the true
          center (see .kanz-particle-dot-N, index.css) — rotating swings it
          around the core in an orbit, and scaling *at that same center
          origin* moves the point closer to/further from center along its
          current angle for free, which is what reads as a particle
          drifting in toward the core ("merging") and back out again. */}
      {animated &&
        PARTICLE_START.slice(0, particleCount).map((pos, i) => (
          <circle
            key={i}
            className={`kanz-particle-dot-${i + 1}`}
            cx={pos.cx}
            cy={pos.cy}
            r="1.15"
            fill="var(--kanz-primary-glow)"
          />
        ))}
    </svg>
  )
}
