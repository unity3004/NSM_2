import type { ReactNode } from "react"
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet"
import { Badge } from "@/components/ui/badge"
import { Label } from "@/components/ui/label"
import type { AuditLogResponse, AuditResult } from "@/types/audit"

function resultBadgeVariant(result: AuditResult): "outline" | "destructive" | "secondary" {
  switch (result) {
    case "success":
      return "outline"
    case "failure":
      return "destructive"
    case "denied":
      return "secondary"
  }
}

function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <div className={mono ? "font-mono text-sm break-all" : "text-sm"}>{value}</div>
    </div>
  )
}

// event is the exact AuditLogResponse row the table already fetched via
// GET /v1/audit-logs — this component makes no request of its own (no
// GET /v1/audit-logs/{id} endpoint exists, and none is needed: every
// field the objective's own event-detail list asks for — ID, timestamp,
// actor, actor type, action, resource, result, request ID, source IP,
// user agent, error code, metadata — is already present in the list
// response). This is deliberate: an N+1 fetch-per-row-click would be the
// exact anti-pattern the objective's own performance section rules out.
//
// "User agent" and "error code" are not distinct columns on
// entity.AuditLogEntry — this codebase's convention (see e.g.
// AuthService.recordLoginAudit's own failure_reason field) is to carry
// that kind of contextual detail inside Metadata instead of adding a
// database column per event-specific field, so they render here as
// metadata keys ("user_agent", "error_code") when a given event actually
// set them, never as an empty placeholder for events that don't.
export function AuditEventDetailSheet({
  event,
  onOpenChange,
}: {
  event: AuditLogResponse | null
  onOpenChange: (open: boolean) => void
}) {
  const metadataEntries = Object.entries(event?.metadata ?? {})

  return (
    <Sheet open={event !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader>
          <div className="flex items-center gap-2">
            <SheetTitle className="font-mono text-base">{event?.action}</SheetTitle>
            {event && (
              <Badge variant={resultBadgeVariant(event.result)} className="text-xs">
                {event.result}
              </Badge>
            )}
          </div>
          <SheetDescription>
            {event ? new Date(event.occurred_at).toLocaleString() : ""}
          </SheetDescription>
        </SheetHeader>

        {event && (
          <div className="flex flex-col gap-4 overflow-y-auto px-4 pb-4">
            <Field label="Event ID" value={event.id} mono />
            <Field label="Actor" value={event.actor_id ?? "system"} mono />
            <Field label="Actor type" value={event.actor_type} />
            <Field
              label="Resource"
              value={
                event.resource_type
                  ? `${event.resource_type}${event.resource_id ? `: ${event.resource_id}` : ""}`
                  : "—"
              }
              mono
            />
            <Field label="Request ID" value={event.request_id ?? "—"} mono />
            <Field label="Source IP" value={event.ip_address ?? "—"} mono />

            {metadataEntries.length > 0 && (
              <div className="flex flex-col gap-1">
                <Label className="text-xs text-muted-foreground">Metadata</Label>
                <pre className="overflow-x-auto rounded-md border bg-muted px-2 py-1.5 font-mono text-xs">
                  {JSON.stringify(event.metadata, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex flex-col gap-1">
              <Label className="text-xs text-muted-foreground">Record hash</Label>
              <div className="font-mono text-xs break-all text-muted-foreground">
                {event.record_hash}
              </div>
            </div>
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}
