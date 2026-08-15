import { useState, type ReactNode } from "react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ApiError } from "@/lib/apiError"
import { Toaster } from "@/components/ui/sonner"

export function AppProviders({ children }: { children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30_000,
            retry: (failureCount, error) => {
              // Never retry an authentication or abuse-protection outcome:
              // a 401 is already handled once by httpClient's own
              // refresh-and-retry (verified against the real backend this
              // sprint), and auto-retrying a 429/RATE_LIMITED or
              // 423/ACCOUNT_LOCKED would compound the very abuse those
              // real, Redis- and Postgres-backed controls exist to stop.
              if (error instanceof ApiError) {
                if (error.status === 401 || error.isRateLimited || error.isAccountLocked) {
                  return false
                }
              }
              return failureCount < 2
            },
          },
        },
      }),
  )

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      <Toaster />
    </QueryClientProvider>
  )
}
