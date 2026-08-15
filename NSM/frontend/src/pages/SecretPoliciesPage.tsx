import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useSecretPolicies } from "@/features/secretPolicies/useSecretPolicies"
import { CreatePolicyDialog } from "@/features/secretPolicies/CreatePolicyDialog"
import { PolicyDetailSheet } from "@/features/secretPolicies/PolicyDetailSheet"
import { usePermission } from "@/features/auth/usePermission"

// REAL API DATA: every row comes from GET /v1/secret-policies
// (secret_policies:read-gated) — these are path-scoped authorization
// policies that actually exist in the database (Sprint 4 Task 2), layered
// on top of (never replacing) the Roles page's own resource:action
// permissions: a role still needs the underlying secrets:* permission
// first, and a policy assigned to that role then decides which secret
// *paths* it may reach.
export function SecretPoliciesPage() {
  const { data, isLoading, isError } = useSecretPolicies()
  const [selectedPolicyId, setSelectedPolicyId] = useState<string | null>(null)
  const canCreate = usePermission("secret_policies:create")

  const policies = data?.data ?? []

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Secret policies</h1>
          <p className="text-sm text-muted-foreground">
            Policies restrict which secret paths a role's members may reach. A role must still hold
            the underlying secrets:* permission — a policy narrows that grant, it never widens it.
          </p>
        </div>
        {canCreate && <CreatePolicyDialog />}
      </div>

      {isError && (
        <p className="text-sm text-muted-foreground">
          You don't have permission to view secret policies, or something went wrong.
        </p>
      )}

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}

      {!isLoading && !isError && policies.length === 0 && (
        <p className="text-sm text-muted-foreground">No secret policies yet.</p>
      )}

      {!isLoading && !isError && policies.length > 0 && (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Scope</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((policy) => (
                <TableRow
                  key={policy.id}
                  className="cursor-pointer"
                  onClick={() => setSelectedPolicyId(policy.id)}
                >
                  <TableCell className="font-medium">{policy.name}</TableCell>
                  <TableCell className="max-w-xs truncate text-muted-foreground">
                    {policy.description ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-xs">
                      {policy.organization_id ? "This organization" : "Platform-wide"}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <PolicyDetailSheet
        policyId={selectedPolicyId}
        onOpenChange={(open) => !open && setSelectedPolicyId(null)}
      />
    </div>
  )
}
