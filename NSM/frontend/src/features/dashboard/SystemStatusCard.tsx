import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { checkHealth } from "@/services/systemApi"
import { cn } from "@/lib/utils"

// REAL API DATA: a live call to GET /healthz. This is the only genuine
// "system status" signal the backend exposes today — no synthetic uptime
// percentage or fabricated metric is shown in its place.
export function SystemStatusCard() {
  const { isSuccess, isError, isLoading } = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => checkHealth(signal),
    refetchInterval: 30_000,
    retry: false,
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>System status</CardTitle>
        <CardDescription>Live check against the API's health endpoint.</CardDescription>
      </CardHeader>
      <CardContent className="flex items-center gap-2 text-sm">
        <span
          className={cn(
            "size-2 rounded-full",
            isLoading && "bg-muted-foreground/40",
            isSuccess && "bg-emerald-400",
            isError && "bg-red-400",
          )}
        />
        <span className="text-foreground">
          {isLoading && "Checking…"}
          {isSuccess && "API is online"}
          {isError && "API is unreachable"}
        </span>
      </CardContent>
    </Card>
  )
}
