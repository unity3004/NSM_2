// Mirrors auth-service/internal/dto/common.go's Error/ErrorBody/FieldError
// and PageMeta exactly — the shape every non-2xx response and every list
// endpoint actually returns.

export interface FieldError {
  field: string
  issue: string
}

export interface ErrorBody {
  code: string
  message: string
  details?: FieldError[]
  request_id: string
}

/** The raw envelope every non-2xx JSON response uses: {"error": {...}}. */
export interface ErrorEnvelope {
  error: ErrorBody
}

export interface PageMeta {
  next_cursor: string | null
  has_more: boolean
  limit: number
}

export interface ListResponse<T> {
  data: T[]
  page: PageMeta
}
