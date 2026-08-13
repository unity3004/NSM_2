import { useQuery } from "@tanstack/react-query"
import { getLease, listLeases } from "@/services/leasesApi"

export function useLeases() {
  return useQuery({
    queryKey: ["leases"],
    queryFn: ({ signal }) => listLeases(signal),
  })
}

export function useLease(id: string | null) {
  return useQuery({
    queryKey: ["leases", id],
    queryFn: ({ signal }) => getLease(id as string, signal),
    enabled: id !== null,
  })
}
