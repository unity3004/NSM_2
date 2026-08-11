import { Outlet } from "react-router-dom"
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
import { ShieldCheck, LayoutDashboard, KeyRound, Users, ScrollText, LogOut } from "lucide-react"
import { useCurrentUser } from "@/features/users/useCurrentUser"
import { useLogout } from "@/features/auth/useLogout"

// Shown but disabled — the sidebar's information architecture is honest
// about what this product will eventually cover without pretending these
// surfaces are built yet.
const futureNavItems = [
  { label: "Secrets", icon: KeyRound },
  { label: "Access", icon: Users },
  { label: "Audit", icon: ScrollText },
]

export function AppLayout() {
  const { data: user } = useCurrentUser()
  const logout = useLogout()

  const initials = user?.email ? user.email.slice(0, 2).toUpperCase() : "?"

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <div className="flex items-center gap-2 px-2 py-1.5">
            <ShieldCheck className="size-5 shrink-0 text-primary" strokeWidth={1.75} />
            <span className="text-sm font-semibold tracking-tight group-data-[collapsible=icon]:hidden">
              Vaultis
            </span>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton isActive tooltip="Dashboard">
                    <LayoutDashboard />
                    <span>Dashboard</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
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
          <span className="text-sm font-medium">Dashboard</span>

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
                <DropdownMenuLabel className="truncate text-xs font-normal text-muted-foreground">
                  {user?.email ?? "…"}
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
