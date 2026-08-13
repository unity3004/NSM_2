import { useMutation, useQueryClient } from "@tanstack/react-query"
import {
  assignServiceAccountRole,
  createCredential,
  deleteServiceAccount,
  removeServiceAccountRole,
  revokeCredential,
  rotateCredential,
  updateServiceAccount,
} from "@/services/serviceAccountsApi"
import type { ApiKeyCreateRequest, ServiceAccountUpdateRequest } from "@/types/serviceAccount"

export function useUpdateServiceAccount(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: ServiceAccountUpdateRequest) => updateServiceAccount(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["service-accounts"] })
      queryClient.invalidateQueries({ queryKey: ["service-accounts", id] })
    },
  })
}

export function useDeleteServiceAccount() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteServiceAccount(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["service-accounts"] })
    },
  })
}

export function useAssignServiceAccountRole(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) => assignServiceAccountRole(id, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["service-accounts", id] })
    },
  })
}

export function useRemoveServiceAccountRole(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) => removeServiceAccountRole(id, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["service-accounts", id] })
    },
  })
}

export function useCreateCredential(serviceAccountId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: Omit<ApiKeyCreateRequest, "owner_service_account_id">) =>
      createCredential({ ...payload, owner_service_account_id: serviceAccountId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["service-accounts", serviceAccountId, "credentials"] })
    },
  })
}

export function useRevokeCredential(serviceAccountId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (credentialId: string) => revokeCredential(credentialId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["service-accounts", serviceAccountId, "credentials"] })
    },
  })
}

export function useRotateCredential(serviceAccountId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (credentialId: string) => rotateCredential(credentialId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["service-accounts", serviceAccountId, "credentials"] })
    },
  })
}
