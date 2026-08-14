import { KanzMark } from "@/components/brand/KanzMark"
import { cn } from "@/lib/utils"

// The one place the product name and mark are defined — every surface that
// shows branding (the sidebar, the login page's identity panel) renders
// this component rather than repeating "KANZ" + KanzMark inline, so there
// is exactly one place to update if either ever changes.
interface BrandProps {
  size?: "sm" | "lg"
  className?: string
  /** Extra classes on the wordmark span only — e.g. AppLayout's collapsed
   * sidebar state needs to hide the text while keeping the icon visible,
   * which has to target the span specifically, not the whole component. */
  textClassName?: string
  /** The continuous idle motion (slow core pulse, tiny fragment drift) —
   * see KanzMark's own doc comment. Opt-in and off by default: the spec's
   * "compact animated emblem" is specifically a sidebar treatment, not a
   * blanket "the logo always moves" rule, so AuthLayout's login-page brand
   * stays static and only AppLayout's sidebar usage passes this. */
  animated?: boolean
}

export function Brand({ size = "sm", className, textClassName, animated = false }: BrandProps) {
  return (
    <div className={cn("flex items-center gap-2 text-foreground", className)}>
      <KanzMark size={size === "lg" ? 28 : 20} variant={animated ? "idle" : "static"} className="shrink-0" />
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
