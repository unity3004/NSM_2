import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet"
import { Badge } from "@/components/ui/badge"
import type { RoleWithPermissionsResponse } from "@/types/rbac"

export function RoleDetailSheet({
  role,
  onOpenChange,
}: {
  role: RoleWithPermissionsResponse | null
  onOpenChange: (open: boolean) => void
}) {
  return (
    <Sheet open={role !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-md">
        <SheetHeader>
          <SheetTitle>{role?.name}</SheetTitle>
          <SheetDescription>{role?.description ?? "No description."}</SheetDescription>
        </SheetHeader>

        {role && (
          <div className="flex flex-col gap-6 overflow-y-auto px-4 pb-6">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Users with this role</span>
              <span className="font-medium">{role.user_count}</span>
            </div>

            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-medium">Permissions</h3>
              {role.permissions.length === 0 && (
                <p className="text-sm text-muted-foreground">No permissions granted.</p>
              )}
              <ul className="flex flex-col gap-1.5">
                {role.permissions.map((p) => (
                  <li key={p.id} className="flex items-center gap-2 text-sm">
                    <Badge variant="outline" className="font-mono text-xs">
                      {p.name}
                    </Badge>
                    {p.description && <span className="text-xs text-muted-foreground">{p.description}</span>}
                  </li>
                ))}
              </ul>
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}
