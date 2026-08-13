import { httpClient } from "@/services/httpClient"
import type { ListResponse } from "@/types/common"
import type {
  LeaseCreatedResponse,
  LeaseCreateRequest,
  LeaseRenewRequest,
  LeaseResponse,
} from "@/types/lease"

/** GET /v1/leases. Every lease the caller owns, or — if the caller holds
 * leases:read — every lease in the organization. Requires only
 * authentication; no permission gates this endpoint on the backend. */
export function listLeases(signal?: AbortSignal): Promise<ListResponse<LeaseResponse>> {
  return httpClient.get<ListResponse<LeaseResponse>>("/v1/leases", { signal })
}

/** GET /v1/leases/{id} — metadata only, never the credential (see
 * LeaseResponse's own doc comment). Requires ownership or leases:read. */
export function getLease(id: string, signal?: AbortSignal): Promise<LeaseResponse> {
  return httpClient.get<LeaseResponse>(`/v1/leases/${encodeURIComponent(id)}`, { signal })
}

/** POST /v1/leases. Requires secrets:read + path-policy access to the
 * requested path + leases:create — holding secrets:read alone is
 * deliberately not enough (Sprint 5 Task 2's own "must not obtain dynamic
 * credentials merely because it can access static secrets" rule). The
 * response's `credential` field is the only time the raw dynamic
 * credential is ever returned. */
export function createLease(payload: LeaseCreateRequest): Promise<LeaseCreatedResponse> {
  return httpClient.post<LeaseCreatedResponse>("/v1/leases", payload, { retryOn401: false })
}

/** POST /v1/leases/{id}/renew. Owner-only — there is no administrative
 * override for renewal (see the backend's own LeaseService.Renew doc
 * comment). Fails on a revoked, expired, or non-renewable lease. */
export function renewLease(id: string, payload: LeaseRenewRequest = {}): Promise<LeaseResponse> {
  return httpClient.post<LeaseResponse>(`/v1/leases/${encodeURIComponent(id)}/renew`, payload, {
    retryOn401: false,
  })
}

/** POST /v1/leases/{id}/revoke. Requires ownership or leases:revoke. */
export function revokeLease(id: string, reason?: string): Promise<void> {
  return httpClient.post<void>(
    `/v1/leases/${encodeURIComponent(id)}/revoke`,
    reason ? { reason } : undefined,
    { retryOn401: false },
  )
}
