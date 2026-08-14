import { Link, Outlet, useLocation } from "react-router-dom"
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
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
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  LayoutDashboard,
  KeyRound,
  Users as UsersIcon,
  ShieldCheck as RolesIcon,
  Lock as PoliciesIcon,
  Bot as ServiceAccountsIcon,
  Timer as LeasesIcon,
  ScrollText,
  Settings as SettingsIcon,
  LogOut,
} from "lucide-react"
import { useCurrentUser } from "@/features/users/useCurrentUser"
import { useLogout } from "@/features/auth/useLogout"
import { Brand } from "@/components/Brand"

// Real routes, gated by what the real backend told us the current user
// can actually do (see useCurrentUser -> GET /v1/users/{id}'s effective
// permissions) — this is advisory UX only, never the enforcement: a user
// without users:read who navigates to /users directly still gets a real
// 403 from GET /v1/users, which that page's own isError state renders as
// an access-denied message. Hiding the link just avoids pointing someone
// at a page the backend is only ever going to refuse.
const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, permission: null },
  { to: "/users", label: "Users", icon: UsersIcon, permission: "users:read" },
  { to: "/roles", label: "Roles", icon: RolesIcon, permission: "roles:read" },
  // Sprint 3 Phase 5: gated on secrets:list, matching GET /v1/secrets'
  // own backend permission requirement exactly (router.go) — the same
  // "hide what the real backend would refuse anyway" convention every
  // other gated item here already follows.
  { to: "/secrets", label: "Secrets", icon: KeyRound, permission: "secrets:list" },
  // Sprint 4 Task 2: gated on secret_policies:read, matching GET
  // /v1/secret-policies' own backend permission requirement exactly
  // (router.go) — the same "hide what the real backend would refuse
  // anyway" convention every other gated item here already follows.
  { to: "/secret-policies", label: "Secret policies", icon: PoliciesIcon, permission: "secret_policies:read" },
  // Sprint 5 Task 1: gated on service_accounts:read, matching GET
  // /v1/service-accounts' own backend permission requirement exactly
  // (router.go) — the same "hide what the real backend would refuse
  // anyway" convention every other gated item here already follows.
  { to: "/service-accounts", label: "Service accounts", icon: ServiceAccountsIcon, permission: "service_accounts:read" },
  // Sprint 5 Task 2: unlike every other gated item above, GET /v1/leases
  // requires no permission at all — every authenticated caller sees their
  // own leases (ownership-filtered on the backend), so this link is
  // always shown, the same "null means always visible" convention
  // Dashboard's own entry already establishes.
  { to: "/leases", label: "Leases", icon: LeasesIcon, permission: null },
  // Sprint 4 Task 3: gated on audit:read, matching GET /v1/audit-logs'
  // own backend permission requirement exactly (router.go) — the same
  // "hide what the real backend would refuse anyway" convention every
  // other gated item here already follows. audit:read is an existing
  // permission (migrations 000022/000023, seeded to Security Engineer
  // and Auditor), not a new one this task introduced.
  { to: "/audit-logs", label: "Audit Logs", icon: ScrollText, permission: "audit:read" },
] as const

// Shown but disabled — the sidebar's information architecture is honest
// about what this product will eventually cover without pretending these
// surfaces are built yet.
const futureNavItems = [{ label: "Settings", icon: SettingsIcon }]

const pageTitles: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/users": "Users",
  "/roles": "Roles",
  "/secrets": "Secrets",
  "/secret-policies": "Secret policies",
  "/service-accounts": "Service accounts",
  "/leases": "Leases",
  "/audit-logs": "Audit Logs",
}

export function AppLayout() {
  const { data: user } = useCurrentUser()
  const logout = useLogout()
  const location = useLocation()

  const initials = user?.email ? user.email.slice(0, 2).toUpperCase() : "?"
  const permissionNames = new Set((user?.permissions ?? []).map((p) => p.name))
  const title = pageTitles[location.pathname] ?? "Dashboard"

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <Brand className="px-2 py-1.5" textClassName="group-data-[collapsible=icon]:hidden" />
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {navItems
                  .filter((item) => item.permission === null || permissionNames.has(item.permission))
                  .map((item) => (
                    <SidebarMenuItem key={item.to}>
                      <SidebarMenuButton asChild isActive={location.pathname === item.to} tooltip={item.label}>
                        <Link to={item.to}>
                          <item.icon />
                          <span>{item.label}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                {futureNavItems.map((item) => (
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
        </SidebarContent>
      </Sidebar>

      <SidebarInset>
        <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger />
          <Separator orientation="vertical" className="h-4" />
          <span className="text-sm font-medium">{title}</span>

          <div className="ml-auto">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  className="flex items-center gap-2 rounded-md p-1 hover:bg-accent"
                  aria-label="Account menu"
                >
                  <Avatar className="size-7">
                    <AvatarFallback className="text-xs">{initials}</AvatarFallback>
                  </Avatar>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel className="flex flex-col gap-0.5 font-normal">
                  <span className="truncate text-sm font-medium text-foreground">
                    {user?.username ?? "…"}
                  </span>
                  <span className="truncate text-xs text-muted-foreground">{user?.email ?? "…"}</span>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
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
          </div>
        </header>

        <main className="flex flex-1 flex-col gap-4 p-4 md:p-6">
          <Outlet />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
