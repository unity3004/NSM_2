import { useCurrentUser } from "@/features/users/useCurrentUser"

/**
 * Whether the current user holds a specific "resource:action" permission —
 * built from the same real, backend-resolved effective-permissions list
 * (GET /v1/users/{id}, see useCurrentUser) AppLayout already uses inline to
 * filter nav items, factored out here so feature code (e.g. the Secrets
 * page's Create/Update/Delete/Reveal controls) doesn't each re-derive its
 * own Set from user.permissions.
 *
 * This is advisory UX only — see AppLayout.tsx's own doc comment on the
 * identical point: hiding or disabling a control here never substitutes
 * for the real, server-side RequirePermission check every write endpoint
 * already enforces. A user without secrets:create who forces the Create
 * button to render (e.g. via devtools) still gets a real 403 from
 * POST /v1/secrets the moment they submit.
 *
 * Returns false (not "unknown"/undefined) while the permission list is
 * still loading, so a control gated by this hook fails closed — hidden
 * until proven allowed, never briefly visible before the real answer
 * arrives.
 */
export function usePermission(permission: string): boolean {
  const { data: user } = useCurrentUser()
  return (user?.permissions ?? []).some((p) => p.name === permission)
}
