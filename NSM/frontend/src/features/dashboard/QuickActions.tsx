import { Link } from "react-router-dom"
import { KeyRound, UserPlus, Zap, Radar, ChevronRight, type LucideIcon } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { usePermission } from "@/features/auth/usePermission"
import { cn } from "@/lib/utils"

/**
 * Real navigation to existing routes/pages — no new backend endpoint, no
 * inline dialogs duplicating what SecretsPage/UsersPage already do. Each
 * create action is gated on the exact permission the target page's own
 * create control (or the backend route it calls) already requires — the
 * same "hide what the backend would refuse anyway" convention the
 * sidebar (AppLayout.tsx) uses, so a lower-privileged viewer never sees
 * an action that would just 403.
 */
const ACTIONS: { label: string; to: string; icon: LucideIcon; permission: string | null }[] = [
  { label: "Create Secret", to: "/secrets", icon: KeyRound, permission: "secrets:create" },
  { label: "Create Identity", to: "/users", icon: UserPlus, permission: "users:create" },
  { label: "View Leases", to: "/leases", icon: Zap, permission: null },
  { label: "Open Audit Explorer", to: "/audit", icon: Radar, permission: "audit:read" },
]

export function QuickActions() {
  return (
    <Card className="w-full lg:w-72 lg:shrink-0">
      <CardHeader>
        <CardTitle>Quick Actions</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-0.5">
        {ACTIONS.map((action) => (
          <QuickAction key={action.to} {...action} />
        ))}
      </CardContent>
    </Card>
  )
}

function QuickAction({
  label,
  to,
  icon: Icon,
  permission,
}: {
  label: string
  to: string
  icon: LucideIcon
  permission: string | null
}) {
  // Rules of hooks: always call this, and always with the same
  // permission every render for a given ACTIONS entry — the list is a
  // static module-level constant, so this is safe.
  const allowed = usePermission(permission ?? "")
  if (permission !== null && !allowed) return null

  return (
    <Link
      to={to}
      className={cn(
        "group flex items-center gap-2.5 rounded-lg px-2.5 py-2.5 text-sm text-foreground",
        "border border-transparent transition-colors duration-[180ms] ease-out",
        "hover:border-kanz-primary/25 hover:bg-kanz-surface-elevated",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kanz-primary/50",
      )}
    >
      <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-kanz-surface-elevated text-kanz-primary transition-[color,filter] duration-[180ms] group-hover:brightness-125">
        <Icon className="size-4" strokeWidth={1.75} aria-hidden="true" />
      </span>
      <span className="flex-1">{label}</span>
      <ChevronRight
        className="size-4 shrink-0 text-muted-foreground transition-[transform,color] duration-[180ms] group-hover:translate-x-0.5 group-hover:text-kanz-primary"
        aria-hidden="true"
      />
    </Link>
  )
}
