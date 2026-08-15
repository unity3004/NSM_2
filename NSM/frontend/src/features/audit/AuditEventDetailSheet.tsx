import { useState, type ReactNode } from "react"
import { Copy, Check } from "lucide-react"
import { toast } from "sonner"
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import {
  actorLabel,
  actorTypeLabel,
  resourceTypeAndPath,
  RESULT_META,
} from "@/features/dashboard/auditDisplay"
import { cn } from "@/lib/utils"
import type { AuditLogResponse } from "@/types/audit"
import type { UserResponse } from "@/types/user"
import type { ServiceAccountResponse } from "@/types/serviceAccount"

function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <div className={mono ? "font-mono text-sm break-all" : "text-sm"}>{value}</div>
    </div>
  )
}

function Divider() {
  return <div className="border-t border-border" />
}

// event is the exact AuditLogResponse row the list already fetched via
// GET /v1/audit-logs — this component makes no request of its own (no
// separate GET /v1/audit-logs/{id} call for a row already in hand) — every
// field the objective's own event-detail list asks for — ID, timestamp,
// actor, actor type, action, resource, result, request ID, source IP,
// metadata — is already present in the list response. This is deliberate:
// an N+1 fetch-per-row-click would be the exact anti-pattern the
// objective's own performance section rules out.
//
// users/serviceAccounts are the same already-loaded lists AuditLogsPage's
// Identity filter and every row already use (actorLabel) — passed down
// rather than re-fetched, so opening an event costs zero extra requests.
export function AuditEventDetailSheet({
  event,
  users,
  serviceAccounts,
  onOpenChange,
}: {
  event: AuditLogResponse | null
  users?: UserResponse[]
  serviceAccounts?: ServiceAccountResponse[]
  onOpenChange: (open: boolean) => void
}) {
  const [copied, setCopied] = useState(false)
  const metadataEntries = Object.entries(event?.metadata ?? {})
  const result = event ? RESULT_META[event.result] : null
  const resource = event ? resourceTypeAndPath(event) : null

  async function copyRequestId() {
    if (!event?.request_id) return
    await navigator.clipboard.writeText(event.request_id)
    setCopied(true)
    toast.success("Request ID copied")
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Sheet
      open={event !== null}
      onOpenChange={(open) => {
        setCopied(false)
        onOpenChange(open)
      }}
    >
      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader>
          <SheetTitle className="font-mono text-base">{event?.action}</SheetTitle>
          {event && result && (
            <span className={cn("flex w-fit items-center gap-1 text-xs font-semibold tracking-wide", result.className)}>
              <result.icon className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
              {result.label}
            </span>
          )}
          <SheetDescription className="sr-only">Audit event details</SheetDescription>
        </SheetHeader>

        {event && (
          <div className="flex flex-col gap-4 overflow-y-auto px-4 pb-4">
            <Field
              label="Identity"
              value={
                <div className="flex items-center gap-2">
                  <span>{actorLabel(event, users, serviceAccounts)}</span>
                  <span className="rounded border border-border px-1.5 py-0.5 text-[0.65rem] font-semibold tracking-wide text-muted-foreground uppercase">
                    {actorTypeLabel(event.actor_type)}
                  </span>
                </div>
              }
            />

            <Divider />

            <Field label="Resource" value={resource ?? "—"} mono={resource !== null} />

            <Divider />

            <Field
              label="Timestamp"
              value={
                <div className="flex flex-col">
                  <span>{new Date(event.occurred_at).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}</span>
                  <span className="text-muted-foreground">{new Date(event.occurred_at).toLocaleTimeString()}</span>
                </div>
              }
            />

            <Divider />

            <Field
              label="Request ID"
              value={
                event.request_id ? (
                  <div className="flex items-center gap-2">
                    <span className="min-w-0 flex-1 truncate">{event.request_id}</span>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 shrink-0 px-2"
                      onClick={copyRequestId}
                    >
                      {copied ? <Check className="size-3.5 text-kanz-success" /> : <Copy className="size-3.5" />}
                      {copied ? "Copied" : "Copy"}
                    </Button>
                  </div>
                ) : (
                  "—"
                )
              }
              mono={Boolean(event.request_id)}
            />

            <Divider />

            <Field label="Source IP" value={event.ip_address ?? "—"} mono />

            {metadataEntries.length > 0 && (
              <>
                <Divider />
                <div className="flex flex-col gap-1">
                  <Label className="text-xs text-muted-foreground">Event Metadata</Label>
                  <details className="group">
                    <summary className="cursor-pointer text-sm text-kanz-primary transition-colors hover:text-kanz-primary-glow">
                      <span className="group-open:hidden">Expand</span>
                      <span className="hidden group-open:inline">Collapse</span>
                    </summary>
                    <pre className="mt-2 overflow-x-auto rounded-md border border-border bg-muted px-2 py-1.5 font-mono text-xs">
                      {JSON.stringify(event.metadata, null, 2)}
                    </pre>
                  </details>
                </div>
              </>
            )}

            <Divider />

            <Field label="Record hash" value={event.record_hash} mono />
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}
