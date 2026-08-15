import { Link, Outlet, useLocation } from "react-router-dom"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Separator } from "@/components/ui/separator"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  LayoutDashboard,
  KeyRound,
  Users as UsersIcon,
  UserCog as RolesIcon,
  ShieldCheck as PoliciesIcon,
  Bot as ServiceAccountsIcon,
  Zap as LeasesIcon,
  Radar as AuditIcon,
  Settings as SettingsIcon,
  LogOut,
  ChevronsUpDown,
} from "lucide-react"
import { useCurrentUser } from "@/features/users/useCurrentUser"
import { useLogout } from "@/features/auth/useLogout"
import { useLeases } from "@/features/leases/useLeases"
import { Brand } from "@/components/Brand"
import { cn } from "@/lib/utils"

// Real routes, gated by what the real backend told us the current user
// can actually do (see useCurrentUser -> GET /v1/users/{id}'s effective
// permissions) — this is advisory UX only, never the enforcement: a user
// without users:read who navigates to /users directly still gets a real
// 403 from GET /v1/users, which that page's own isError state renders as
// an access-denied message. Hiding the link just avoids pointing someone
// at a page the backend is only ever going to refuse.
//
// Grouped into the KANZ shell's information architecture (Overview /
// Identity / Secrets / Security / System). Users and Roles don't appear
// in the sidebar brief's own hierarchy, which names only Dashboard,
// Secrets, Dynamic Leases, Policies, Service Accounts, Audit Explorer,
// and Settings — but removing their nav links would remove real,
// already-shipped functionality every phase of this rebrand has said not
// to touch, so they keep their own "Identity" group rather than being
// dropped (the same call made in the Phase 1 shell pass). Every route and
// permission gate below is unchanged — only labels, icons, and visual
// treatment move.
const navGroups = [
  {
    label: "Overview",
    items: [{ to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, permission: null }],
  },
  {
    label: "Identity",
    items: [
      { to: "/users", label: "Users", icon: UsersIcon, permission: "users:read" },
      { to: "/roles", label: "Roles", icon: RolesIcon, permission: "roles:read" },
    ],
  },
  {
    label: "Secrets",
    items: [
      // Sprint 3 Phase 5: gated on secrets:list, matching GET /v1/secrets'
      // own backend permission requirement exactly (router.go) — the same
      // "hide what the real backend would refuse anyway" convention every
      // other gated item here already follows.
      { to: "/secrets", label: "Secrets", icon: KeyRound, permission: "secrets:list" },
      // Sprint 5 Task 2: unlike every other gated item here, GET /v1/leases
      // requires no permission at all — every authenticated caller sees
      // their own leases (ownership-filtered on the backend), so this link
      // is always shown, the same "null means always visible" convention
      // Dashboard's own entry already establishes.
      { to: "/leases", label: "Dynamic Leases", icon: LeasesIcon, permission: null },
    ],
  },
  {
    label: "Security",
    items: [
      // Sprint 4 Task 2: gated on secret_policies:read, matching GET
      // /v1/secret-policies' own backend permission requirement exactly
      // (router.go) — the same "hide what the real backend would refuse
      // anyway" convention every other gated item here already follows.
      { to: "/secret-policies", label: "Policies", icon: PoliciesIcon, permission: "secret_policies:read" },
      // Sprint 5 Task 1: gated on service_accounts:read, matching GET
      // /v1/service-accounts' own backend permission requirement exactly
      // (router.go) — the same "hide what the real backend would refuse
      // anyway" convention every other gated item here already follows.
      { to: "/service-accounts", label: "Service Accounts", icon: ServiceAccountsIcon, permission: "service_accounts:read" },
      // Sprint 4 Task 3: gated on audit:read, matching GET /v1/audit-logs'
      // own backend permission requirement exactly (router.go) — the same
      // "hide what the real backend would refuse anyway" convention every
      // other gated item here already follows. audit:read is an existing
      // permission (migrations 000022/000023, seeded to Security Engineer
      // and Auditor), not a new one this task introduced.
      { to: "/audit", label: "Audit Explorer", icon: AuditIcon, permission: "audit:read" },
    ],
  },
] as const

// Shown but disabled — the sidebar's information architecture is honest
// about what this product will eventually cover without pretending these
// surfaces are built yet.
const futureNavGroups = [{ label: "System", items: [{ label: "Settings", icon: SettingsIcon }] }]

const pageTitles: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/users": "Users",
  "/roles": "Roles",
  "/secrets": "Secrets",
  "/secret-policies": "Policies",
  "/service-accounts": "Service Accounts",
  "/leases": "Dynamic Leases",
  "/audit": "Audit Explorer",
}

export function AppLayout() {
  const { data: user } = useCurrentUser()
  const logout = useLogout()
  const location = useLocation()
  // Real GET /v1/leases call (the identical hook the Leases page itself
  // uses) — the sidebar's own live indicator on "Dynamic Leases" reflects
  // this, never a fabricated status. If the request hasn't resolved yet
  // or fails, isLeasesActive is simply false: no dot, not a misleading
  // fallback dot.
  const leases = useLeases()
  const hasActiveLeases = leases.data?.data.some((l) => l.status === "active") ?? false

  const initials = user?.email ? user.email.slice(0, 2).toUpperCase() : "?"
  const permissionNames = new Set((user?.permissions ?? []).map((p) => p.name))
  const title = pageTitles[location.pathname] ?? "Dashboard"
  // The real role grant name from GET /v1/users/{id} (e.g. "Platform
  // Administrator") — never the illustrative "Administrator" a design
  // brief might show as an example, and never fabricated when a user
  // happens to hold no role at all.
  const primaryRole = user?.roles[0]?.role_name

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <div className="flex items-center gap-2 px-2 py-1.5">
            <Brand animated />
            <span className="truncate text-[0.65rem] font-medium tracking-wide text-sidebar-foreground/50 group-data-[collapsible=icon]:hidden">
              Security Platform
            </span>
          </div>
        </SidebarHeader>
        <SidebarContent>
          {navGroups.map((group) => {
            const visibleItems = group.items.filter(
              (item) => item.permission === null || permissionNames.has(item.permission),
            )
            if (visibleItems.length === 0) return null
            return (
              <SidebarGroup key={group.label}>
                <SidebarGroupLabel className="text-[0.6875rem] font-semibold tracking-[0.08em] uppercase">
                  {group.label}
                </SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {visibleItems.map((item) => (
                      <SidebarMenuItem key={item.to} className="relative">
                        <SidebarMenuButton asChild isActive={location.pathname === item.to} tooltip={item.label}>
                          <Link to={item.to}>
                            <item.icon />
                            <span>{item.label}</span>
                          </Link>
                        </SidebarMenuButton>
                        {/* Dynamic Leases' own live indicator — a small
                            dot, not a fabricated countdown, shown only
                            when the real lease list above found at least
                            one lease with status "active". */}
                        {item.to === "/leases" && hasActiveLeases && (
                          <span
                            aria-label="Active leases present"
                            className="kanz-lease-dot pointer-events-none absolute top-1/2 right-2 size-1.5 -translate-y-1/2 rounded-full bg-kanz-primary group-data-[collapsible=icon]:hidden"
                          />
                        )}
                      </SidebarMenuItem>
                    ))}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            )
          })}
          {futureNavGroups.map((group) => (
            <SidebarGroup key={group.label}>
              <SidebarGroupLabel className="text-[0.6875rem] font-semibold tracking-[0.08em] uppercase">
                {group.label}
              </SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.map((item) => (
                    <SidebarMenuItem key={item.label}>
                      <SidebarMenuButton disabled tooltip={`${item.label} — coming soon`}>
                        <item.icon />
                        <span>{item.label}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}
        </SidebarContent>

        {/* User area: real identity (email + the real role grant name,
            never a hard-coded example), Logout via the app's existing
            useLogout mutation — nothing here is new functionality, just
            relocated from the topbar into the sidebar's own footer. */}
        <SidebarFooter>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className={cn(
                  "flex w-full items-center gap-2 rounded-md p-2 text-left text-sm",
                  "transition-colors duration-150 hover:bg-sidebar-accent",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring",
                )}
                aria-label="Account menu"
              >
                <Avatar className="size-7 shrink-0">
                  <AvatarFallback className="text-xs">{initials}</AvatarFallback>
                </Avatar>
                <div className="flex min-w-0 flex-1 flex-col group-data-[collapsible=icon]:hidden">
                  <span className="truncate text-xs font-medium text-sidebar-foreground">
                    {user?.email ?? "…"}
                  </span>
                  <span className="truncate text-[0.65rem] text-sidebar-foreground/50">
                    {primaryRole ?? "Member"}
                  </span>
                </div>
                <ChevronsUpDown className="size-3.5 shrink-0 text-sidebar-foreground/40 group-data-[collapsible=icon]:hidden" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" side="top" className="w-56">
              <DropdownMenuItem
                variant="destructive"
                disabled={logout.isPending}
                onSelect={(event) => {
                  // Radix closes the menu (and would unmount this item)
                  // on select by default; the mutation itself is
                  // unaffected either way, but preventing the default
                  // keeps "Logging out…" visible on this item instead of
                  // the menu vanishing mid-request.
                  event.preventDefault()
                  logout.mutate()
                }}
              >
                <LogOut />
                {logout.isPending ? "Logging out…" : "Log out"}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset>
        <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger />
          <Separator orientation="vertical" className="h-4" />
          <span className="text-sm font-medium">{title}</span>
        </header>

        {/* mx-auto max-w-[1600px] here — not per-page — is what keeps every
            route from stretching edge-to-edge on an ultrawide display
            (KANZ Phase 9's own "do not simply stretch content to 100%
            viewport width" requirement), applied once so no page has to
            remember to opt in. Most pages don't need it below ~1600px;
            it only ever engages on genuinely wide viewports. */}
        <main className="flex flex-1 flex-col p-4 md:p-6">
          <div className="mx-auto flex w-full max-w-[1600px] flex-1 flex-col">
            <Outlet />
          </div>
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
