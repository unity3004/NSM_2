// Mirrors auth-service/internal/dto/lease.go exactly — Sprint 5 Task 2's
// dynamic-secret leasing: a temporary grant tracking a dynamically-issued
// credential's lifecycle, never the credential itself outside its one
// creation response. See LeaseCreatedResponse's own doc comment below for
// why Credential exists on exactly one of these types and no other.

export type LeaseStatus = "active" | "revoked" | "expired"

/** GET/POST/renew/revoke's shared metadata shape — deliberately no field
 * here could ever hold credential material; see LeaseCreatedResponse for
 * the one response type that does. */
export interface LeaseResponse {
  lease_id: string
  lease_type: string
  resource_path: string
  status: LeaseStatus
  renewable: boolean
  ttl: string
  created_at: string
  expires_at: string
  revoked_at?: string | null
  /** Safe, non-sensitive provider context (Sprint 5 Task 3) — e.g.
   * {"username": "vlt_...", "database": "payment_db", "role_template":
   * "payment-readonly"} for a Postgres lease. Never a password; see
   * dto.LeaseResponse.ProviderMetadata's own doc comment for why this
   * field's absence of credential material is a type-level guarantee,
   * not a convention. */
  provider_metadata?: Record<string, unknown>
}

/** POST /v1/leases' response — the one and only place a lease's raw
 * dynamic credential is ever returned. Never persisted anywhere the
 * frontend can read it back from; closing the dialog that shows it is the
 * point of no return, the same guarantee ApiKeyCreatedResponse.secret
 * already makes for service-account credentials. */
export interface LeaseCreatedResponse extends LeaseResponse {
  credential: Record<string, string>
}

export interface LeaseCreateRequest {
  type: string
  path: string
  /** Selects one entry from an operator-configured role-template catalog
   * (Sprint 5 Task 3) — e.g. "payment-readonly" for a Postgres lease.
   * Ignored by providers with nothing to select (dev-credential). Never
   * a database, schema, or privilege list — those come only from the
   * backend's own configuration. */
  role?: string
  /** Go duration syntax (e.g. "1h", "30m"). Omitted means "use the
   * server's configured default TTL" — never send "0" or a negative
   * value to mean that; the backend rejects both outright. */
  ttl?: string
  renewable?: boolean
}

export interface LeaseRenewRequest {
  ttl?: string
}

export interface LeaseRevokeRequest {
  reason?: string
}
