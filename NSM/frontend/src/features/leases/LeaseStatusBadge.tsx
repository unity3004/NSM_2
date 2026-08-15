import { STATUS_META, type DisplayStatus } from "@/features/leases/leaseDisplay"
import { StatusBadge } from "@/components/StatusBadge"
import { cn } from "@/lib/utils"

export function LeaseStatusBadge({ status, className }: { status: DisplayStatus; className?: string }) {
  const meta = STATUS_META[status]
  return <StatusBadge icon={meta.icon} label={meta.label} className={cn(meta.textClassName, className)} />
}
