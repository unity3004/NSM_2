import { useMutation, useQueryClient } from "@tanstack/react-query"
import { createLease, renewLease, revokeLease } from "@/services/leasesApi"
import type { LeaseCreateRequest, LeaseRenewRequest } from "@/types/lease"

export function useCreateLease() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: LeaseCreateRequest) => createLease(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["leases"] })
    },
  })
}

export function useRenewLease(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: LeaseRenewRequest = {}) => renewLease(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["leases"] })
      queryClient.invalidateQueries({ queryKey: ["leases", id] })
    },
  })
}

export function useRevokeLease(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (reason?: string) => revokeLease(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["leases"] })
      queryClient.invalidateQueries({ queryKey: ["leases", id] })
    },
  })
}
