/**
 * The login page's ambient "security network" — four interactive nodes
 * (Identity/Secrets/Leases/Audit) connected by thin, low-opacity lines to
 * the center, sitting behind the real KanzLogo mark (rendered separately
 * by AuthLayout, on top of this). This is deliberately NOT a second logo:
 * it has no independent identity of its own, just a subtle conceptual
 * backdrop for the one real mark. Pure SVG, no new dependency.
 *
 * Each node is a real, keyboard-focusable SVG <g role="button"> — not
 * decoration a screen reader or keyboard user can't reach. They perform
 * no navigation and have no side effect (nothing here could touch
 * authentication, routing, or any real capability): hovering/focusing one
 * purely brightens that node, its own connecting line, and the central
 * core, via the .kanz-node/.kanz-line/.kanz-core-response rules in
 * index.css — all CSS `:hover`/`:focus`/`:has()`, no JS state, so this
 * costs nothing in re-renders.
 *
 * `size` scales the whole field uniformly (viewBox stays fixed, only the
 * rendered width/height change) — used to shrink it for the tablet
 * breakpoint in AuthLayout.tsx without a second implementation.
 */
const NODES = [
  { key: "identity", label: "Identity", x: 140, y: 8 },
  { key: "secrets", label: "Secrets", x: 272, y: 140 },
  { key: "leases", label: "Leases", x: 140, y: 272 },
  { key: "audit", label: "Audit", x: 8, y: 140 },
] as const

// Non-identical durations/delays per node — see KanzLogo's own particle
// design for the same "avoid four things animating in perfect lockstep"
// reasoning.
const IDLE_TIMING: Record<(typeof NODES)[number]["key"], { duration: string; delay: string }> = {
  identity: { duration: "3.6s", delay: "0ms" },
  secrets: { duration: "4.1s", delay: "-900ms" },
  leases: { duration: "3.3s", delay: "-1800ms" },
  audit: { duration: "4.4s", delay: "-2700ms" },
}

export function SecurityCoreField({ size = 280 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 280 280"
      fill="none"
      className="kanz-security-field pointer-events-none absolute inset-0 m-auto overflow-visible"
    >
      <g pointerEvents="none">
        {NODES.map((n) => (
          <line
            key={n.key}
            className={`kanz-line kanz-line--${n.key}`}
            x1="140"
            y1="140"
            x2={n.x + 6}
            y2={n.y + 6}
            stroke="var(--kanz-primary)"
            strokeOpacity="0.16"
            strokeWidth="1"
            strokeDasharray="4 6"
          />
        ))}
      </g>

      {NODES.map((n) => (
        <g
          key={n.key}
          className={`kanz-node kanz-node--${n.key}`}
          style={{ animationDuration: IDLE_TIMING[n.key].duration, animationDelay: IDLE_TIMING[n.key].delay }}
          tabIndex={0}
          role="button"
          aria-label={`${n.label} — one of four KANZ security capabilities`}
          pointerEvents="all"
        >
          {/* Radial glow halo — invisible at rest, fades in on hover/focus. */}
          <circle className="kanz-node-halo" cx={n.x + 6} cy={n.y + 6} r="16" fill="var(--kanz-primary-glow)" />
          <rect
            className="kanz-node-shape"
            x={n.x}
            y={n.y}
            width="12"
            height="12"
            rx="2.5"
            fill="var(--kanz-surface-elevated)"
            stroke="var(--kanz-primary)"
            strokeOpacity="0.55"
            strokeWidth="1"
            transform={`rotate(45 ${n.x + 6} ${n.y + 6})`}
          />
          <text
            className="kanz-node-label"
            x={n.x + 6}
            y={n.label === "Identity" ? n.y - 8 : n.y + 24}
            textAnchor="middle"
            fontSize="8"
            letterSpacing="0.08em"
            fill="var(--kanz-text-muted)"
            style={{ textTransform: "uppercase" }}
          >
            {n.label}
          </text>
        </g>
      ))}
    </svg>
  )
}
