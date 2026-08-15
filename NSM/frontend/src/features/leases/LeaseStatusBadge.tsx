import { STATUS_META, type DisplayStatus } from "@/features/leases/leaseDisplay"
import { cn } from "@/lib/utils"

/** A restrained status pill — icon + text, never color alone (the icon
 * shape differs per status too, not just its color). */
export function LeaseStatusBadge({ status, className }: { status: DisplayStatus; className?: string }) {
  const meta = STATUS_META[status]
  return (
    <span className={cn("flex items-center gap-1.5 text-xs font-semibold tracking-wide", meta.textClassName, className)}>
      <meta.icon className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
      {meta.label}
    </span>
  )
}
