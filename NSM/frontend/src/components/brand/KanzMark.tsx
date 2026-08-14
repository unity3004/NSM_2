import type { CSSProperties } from "react"
import { cn } from "@/lib/utils"

/**
 * The KANZ emblem: an abstract "Secure Core" — four geometric fragments
 * (Identity, Policy, Secret, Audit, reading clockwise from the top) orbit
 * a central protected core. Deliberately not a padlock/shield/key — see
 * the brand brief this implements. Every brand surface (sidebar, login,
 * KanzSplash) renders this same SVG rather than four independent drawings,
 * so "what the KANZ mark looks like" has exactly one definition.
 *
 * `variant` controls motion, not geometry — all three variants share the
 * identical paths below:
 *   - "static": no motion (collapsed sidebar rail, anywhere motion would
 *     be noise).
 *   - "idle": the continuous, subtle sidebar treatment — slow core pulse
 *     + tiny per-fragment drift. Runs via the .kanz-mark-idle CSS class
 *     (index.css), not inline keyframes, so prefers-reduced-motion is
 *     handled in exactly one place for every consumer.
 *   - "splash": the one-time entrance sequence KanzSplash plays — each
 *     fragment gets its own stagger via the --kanz-stagger/--kanz-from-*
 *     custom properties set below, consumed by the .kanz-splash-fragment
 *     animation (index.css).
 */
interface KanzMarkProps {
  size?: number
  variant?: "static" | "idle" | "splash"
  className?: string
}

const FRAGMENTS = [
  // label is documentation only (identity/policy/secret/audit), not
  // rendered — the mark is meant to read as one abstract emblem, not four
  // labeled icons.
  { label: "identity", cx: 20, cy: 6, fromX: 0, fromY: -14 },
  { label: "policy", cx: 34, cy: 20, fromX: 14, fromY: 0 },
  { label: "secret", cx: 20, cy: 34, fromX: 0, fromY: 14 },
  { label: "audit", cx: 6, cy: 20, fromX: -14, fromY: 0 },
] as const

export function KanzMark({ size = 24, variant = "static", className }: KanzMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      role="img"
      aria-label="KANZ"
      className={cn(variant === "idle" && "kanz-mark-idle", className)}
    >
      <defs>
        <linearGradient id="kanz-core-gradient" x1="14" y1="14" x2="26" y2="26" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="var(--kanz-primary-glow)" />
          <stop offset="100%" stopColor="var(--kanz-secondary)" />
        </linearGradient>
      </defs>

      {/* Connective lines — the four fragments belong to one system, not
          four unrelated shapes. */}
      <g stroke="var(--kanz-border)" strokeWidth="1" strokeDasharray="1.5 2">
        {FRAGMENTS.map((f) => (
          <line key={f.label} x1="20" y1="20" x2={f.cx} y2={f.cy} />
        ))}
      </g>

      {/* Fragments: Identity, Policy, Secret, Audit. */}
      <g>
        {FRAGMENTS.map((f, i) => (
          <rect
            key={f.label}
            className={cn(
              variant === "idle" && "kanz-mark-fragment",
              variant === "splash" && "kanz-splash-fragment",
            )}
            style={
              variant === "splash"
                ? ({
                    "--kanz-stagger": `${i * 60}ms`,
                    "--kanz-from-x": `${f.fromX}px`,
                    "--kanz-from-y": `${f.fromY}px`,
                    // Tiny, distinct idle drift per fragment (index.css'
                    // kanz-idle-drift reads these) so all four don't move
                    // in perfect lockstep.
                    "--kanz-drift-x": `${f.fromX / 12}px`,
                    "--kanz-drift-y": `${f.fromY / 12}px`,
                  } as CSSProperties)
                : variant === "idle"
                  ? ({
                      "--kanz-drift-x": `${f.fromX / 12}px`,
                      "--kanz-drift-y": `${f.fromY / 12}px`,
                      animationDelay: `${i * 300}ms`,
                    } as CSSProperties)
                  : undefined
            }
            x={f.cx - 3.25}
            y={f.cy - 3.25}
            width="6.5"
            height="6.5"
            rx="1.5"
            fill="var(--kanz-surface-elevated)"
            stroke="var(--kanz-primary)"
            strokeOpacity="0.7"
            strokeWidth="1"
            transform={`rotate(45 ${f.cx} ${f.cy})`}
          />
        ))}
      </g>

      {/* The protected core. */}
      <rect
        className={cn(variant === "idle" && "kanz-mark-core", variant === "splash" && "kanz-splash-core")}
        x="13.5"
        y="13.5"
        width="13"
        height="13"
        rx="3"
        fill="url(#kanz-core-gradient)"
        transform="rotate(45 20 20)"
      />
    </svg>
  )
}
