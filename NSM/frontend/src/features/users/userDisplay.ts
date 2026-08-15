import { CheckCircle2, MinusCircle, Lock, Clock, type LucideIcon } from "lucide-react"
import type { UserStatus } from "@/types/user"

/** Real user_status enum values only — see dto.UserResponse. Same
 * {icon, label, className} shape as leaseDisplay's STATUS_META and
 * dashboard/auditDisplay's RESULT_META, so every domain's status renders
 * through the one shared StatusBadge primitive. */
export const USER_STATUS_META: Record<UserStatus, { icon: LucideIcon; label: string; className: string }> = {
  active: { icon: CheckCircle2, label: "Active", className: "text-kanz-success" },
  disabled: { icon: MinusCircle, label: "Disabled", className: "text-muted-foreground" },
  locked: { icon: Lock, label: "Locked", className: "text-kanz-danger" },
  pending_verification: { icon: Clock, label: "Pending verification", className: "text-kanz-warning" },
}
