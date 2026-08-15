import { CheckCircle2, MinusCircle, XCircle, Clock, type LucideIcon } from "lucide-react"
import type { ApiKeyStatus, ServiceAccountStatus } from "@/types/serviceAccount"

/** Real service_account_status enum values — see dto.ServiceAccountResponse.
 * Same {icon, label, className} shape as leaseDisplay's STATUS_META and
 * users/userDisplay's USER_STATUS_META, rendered through the shared
 * StatusBadge primitive. */
export const SERVICE_ACCOUNT_STATUS_META: Record<ServiceAccountStatus, { icon: LucideIcon; label: string; className: string }> = {
  active: { icon: CheckCircle2, label: "Active", className: "text-kanz-success" },
  disabled: { icon: MinusCircle, label: "Disabled", className: "text-muted-foreground" },
}

/** Real api_key_status enum values — see dto.ApiKeyResponse. */
export const API_KEY_STATUS_META: Record<ApiKeyStatus, { icon: LucideIcon; label: string; className: string }> = {
  active: { icon: CheckCircle2, label: "Active", className: "text-kanz-success" },
  revoked: { icon: XCircle, label: "Revoked", className: "text-kanz-danger" },
  expired: { icon: Clock, label: "Expired", className: "text-muted-foreground" },
}
