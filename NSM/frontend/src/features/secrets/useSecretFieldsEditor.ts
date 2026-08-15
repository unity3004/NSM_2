import { useRef, useState } from "react"

export interface FieldRow {
  id: number
  key: string
  value: string
}

// Mirrors maxSecretRequestBodyBytes in the backend's secret_handler.go —
// checked here purely to fail fast with a clear message instead of a
// generic 400 after a full round trip; the backend's own
// http.MaxBytesReader cap remains the real, authoritative limit.
export const MAX_PAYLOAD_BYTES = 256 * 1024

function rowsFrom(nextId: { current: number }, data?: Record<string, string>): FieldRow[] {
  if (data && Object.keys(data).length > 0) {
    return Object.entries(data).map(([key, value]) => ({ id: nextId.current++, key, value }))
  }
  return [{ id: nextId.current++, key: "", value: "" }]
}

/**
 * Shared state + validation behind the dynamic key/value editor used by
 * both CreateSecretDialog and the update flow in SecretDetailSheet — one
 * place owning "what does a valid secret payload look like" so the two
 * forms can never quietly drift apart on duplicate-key/empty-key/payload-size
 * rules. `initialData`, when given (the update flow's already-revealed
 * current value — see SecretDetailSheet's own doc comment on why that's
 * the only source an edit form is ever pre-filled from, never a fresh
 * fetch), seeds the editable rows; omitted, it starts with one empty row,
 * matching CreateSecretDialog's own starting state.
 */
export function useSecretFieldsEditor(initialData?: Record<string, string>) {
  const nextId = useRef(0)
  const [fields, setFields] = useState<FieldRow[]>(() => rowsFrom(nextId, initialData))

  function addField() {
    setFields((prev) => [...prev, { id: nextId.current++, key: "", value: "" }])
  }
  function removeField(id: number) {
    setFields((prev) => prev.filter((f) => f.id !== id))
  }
  function updateField(id: number, patch: Partial<Pick<FieldRow, "key" | "value">>) {
    setFields((prev) => prev.map((f) => (f.id === id ? { ...f, ...patch } : f)))
  }
  function reset(nextData?: Record<string, string>) {
    setFields(rowsFrom(nextId, nextData))
  }

  const nonEmptyFields = fields.filter((f) => f.key.trim() !== "")
  const keyCounts = new Map<string, number>()
  for (const f of nonEmptyFields) {
    const k = f.key.trim()
    keyCounts.set(k, (keyCounts.get(k) ?? 0) + 1)
  }
  const duplicateKeys = new Set([...keyCounts.entries()].filter(([, n]) => n > 1).map(([k]) => k))
  const payload = Object.fromEntries(nonEmptyFields.map((f) => [f.key.trim(), f.value]))
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload)).length
  const payloadTooLarge = payloadBytes > MAX_PAYLOAD_BYTES
  const hasNoFields = nonEmptyFields.length === 0
  const isValid = !hasNoFields && duplicateKeys.size === 0 && !payloadTooLarge

  return {
    fields,
    addField,
    removeField,
    updateField,
    reset,
    payload,
    duplicateKeys,
    payloadBytes,
    payloadTooLarge,
    hasNoFields,
    isValid,
  }
}

export type SecretFieldsEditor = ReturnType<typeof useSecretFieldsEditor>
