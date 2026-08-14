import { KanzLogo } from "@/components/brand/KanzLogo"
import { cn } from "@/lib/utils"

// The one place the product name and mark are defined — every surface that
// shows branding (the sidebar, the login page's identity panel) renders
// this component rather than repeating "KANZ" + KanzLogo inline, so there
// is exactly one place to update if either ever changes.
interface BrandProps {
  size?: "sm" | "lg"
  className?: string
  /** Extra classes on the wordmark span only — e.g. AppLayout's collapsed
   * sidebar state needs to hide the text while keeping the icon visible,
   * which has to target the span specifically, not the whole component. */
  textClassName?: string
  /** Only meaningful at size="sm" (see the variant mapping below) — the
   * sidebar's continuous idle motion is opt-in there, off by default, so
   * a compact static mark stays available for chrome that shouldn't move
   * (e.g. AuthLayout's mobile-fallback brand). size="lg" always animates:
   * the KANZ logo brief is explicit that the *large* variant (login,
   * splash, loading) is a continuously-alive treatment unconditionally,
   * not a lower-priority opt-in the way the compact sidebar mark is. */
  animated?: boolean
}

export function Brand({ size = "sm", className, textClassName, animated = false }: BrandProps) {
  const variant = size === "lg" ? "large" : animated ? "sidebar" : "static"

  return (
    <div className={cn("flex items-center gap-2 text-foreground", className)}>
      <KanzLogo variant={variant} className="shrink-0" />
      <span
        className={cn(
          "font-semibold tracking-tight",
          size === "lg" ? "text-2xl" : "text-sm",
          textClassName,
        )}
      >
        KANZ
      </span>
    </div>
  )
}
