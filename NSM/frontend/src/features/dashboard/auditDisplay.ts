import type { AuditLogResponse } from "@/types/audit"
import type { UserResponse } from "@/types/user"
import type { ServiceAccountResponse } from "@/types/serviceAccount"

// Friendly labels for resource_type — never invented data, just a nicer
// name for a real enum value the backend already writes. Falls back to
// the raw resource_type for anything not listed, so an unrecognized
// value still shows *something* real rather than disappearing.
const RESOURCE_TYPE_LABELS: Record<string, string> = {
  audit: "Audit Explorer",
  secret: "Secret",
  lease: "Lease",
  user: "User Account",
  role: "Role",
  session: "Session",
  service_account: "Service Account",
  secret_policy: "Policy",
  encryption_key: "Encryption Key",
  key: "Encryption Key",
  api_key: "API Key",
}

/**
 * A human-readable actor for a real audit row — "admin@example.com"
 * rather than "user · 366e73cc…". Resolved entirely from data this
 * dashboard already fetches for other sections (useUsers/
 * useServiceAccounts — see PrimaryMetrics), never a new lookup call: if
 * the acting user/service account isn't present in that already-loaded
 * page (e.g. it scrolled off, or the list itself failed to load), this
 * honestly falls back to the opaque type + truncated ID rather than
 * guessing a name.
 */
export function actorLabel(
  event: AuditLogResponse,
  users: UserResponse[] | undefined,
  serviceAccounts: ServiceAccountResponse[] | undefined,
): string {
  if (event.actor_type === "user" && event.actor_id) {
    const user = users?.find((u) => u.id === event.actor_id)
    if (user) return user.email
  }
  if (event.actor_type === "service_account" && event.actor_id) {
    const account = serviceAccounts?.find((sa) => sa.id === event.actor_id)
    if (account) return account.name
  }
  if (event.actor_type === "system") return "System"
  if (event.actor_type === "api_key") return "API key"
  return event.actor_id ? `${event.actor_type} ${event.actor_id.slice(0, 8)}…` : event.actor_type
}

/**
 * A human-readable resource for a real audit row — "production/database"
 * rather than "secret (a1b2c3d4…)". Prefers the real path the backend
 * already embeds in metadata for path-addressable resources (SecretService
 * writes `metadata.path`, LeaseService writes `metadata.resource_path` —
 * the same fields the Audit Explorer's own resource-ID/path search reads),
 * falling back to a friendly resource_type label, then the raw
 * resource_type, then null if the event has no resource at all (some
 * event types genuinely don't, e.g. a bare login).
 */
export function resourceLabel(event: AuditLogResponse): string | null {
  const metadata = event.metadata
  const path = metadata?.path ?? metadata?.resource_path
  if (typeof path === "string" && path.length > 0) return path
  if (event.resource_type) return RESOURCE_TYPE_LABELS[event.resource_type] ?? event.resource_type
  return null
}
