import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { History } from "lucide-react"

// UI PLACEHOLDER — deliberately not real data. The audit_logs table and
// repository already exist on the backend, but no HTTP route exposes them
// yet (confirmed by inspecting router.go: only auth + users routes are
// wired). This card must never show fabricated activity rows in their
// place — an honest empty state instead, clearly labeled "Coming soon."
export function RecentActivityPlaceholder() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between">
        <div>
          <CardTitle>Recent activity</CardTitle>
          <CardDescription>Audit trail for this account.</CardDescription>
        </div>
        <Badge variant="outline">Coming soon</Badge>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed py-10 text-center text-sm text-muted-foreground">
          <History className="size-5" strokeWidth={1.5} />
          <p>Activity will appear here once audit log access is available.</p>
        </div>
      </CardContent>
    </Card>
  )
}
