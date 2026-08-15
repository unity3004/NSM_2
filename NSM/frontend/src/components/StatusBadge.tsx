import type { LucideIcon } from "lucide-react"
import { cn } from "@/lib/utils"

/** The one status-indicator treatment used everywhere in KANZ — icon +
 * text, never color alone (the icon shape differs per status too, not
 * just its color). Originally LeaseStatusBadge's own markup; pulled out
 * here so Leases, Audit, Users, and Service Accounts all render their
 * (very different) real status enums through the same visual primitive
 * instead of four near-identical hand-rolled spans. */
export function StatusBadge({
  icon: Icon,
  label,
  className,
}: {
  icon: LucideIcon
  label: string
  className?: string
}) {
  return (
    <span className={cn("inline-flex shrink-0 items-center gap-1.5 text-xs font-semibold tracking-wide", className)}>
      <Icon className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
      {label}
    </span>
  )
}
