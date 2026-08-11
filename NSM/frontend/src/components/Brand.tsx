import { ShieldCheck } from "lucide-react"
import { cn } from "@/lib/utils"

// The one place the product name and mark are defined — every surface that
// shows branding (the sidebar, the login page's identity panel) renders
// this component rather than repeating "Vaultis" + ShieldCheck inline, so
// there is exactly one place to update if either ever changes.
interface BrandProps {
  size?: "sm" | "lg"
  className?: string
  /** Extra classes on the wordmark span only — e.g. AppLayout's collapsed
   * sidebar state needs to hide the text while keeping the icon visible,
   * which has to target the span specifically, not the whole component. */
  textClassName?: string
}

export function Brand({ size = "sm", className, textClassName }: BrandProps) {
  return (
    <div className={cn("flex items-center gap-2 text-foreground", className)}>
      <ShieldCheck
        className={cn(size === "lg" ? "size-7" : "size-5", "shrink-0 text-primary")}
        strokeWidth={1.75}
      />
      <span
        className={cn(
          "font-semibold tracking-tight",
          size === "lg" ? "text-2xl" : "text-sm",
          textClassName,
        )}
      >
        Vaultis
      </span>
    </div>
  )
}
