import { useMemo, useState } from "react"
import { RefreshCw, BarChart3 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuditLogs } from "@/features/audit/useAuditLogs"
import { cn } from "@/lib/utils"

const LABELED_HOURS = new Set([0, 4, 8, 12, 16, 20])
const CHART_WIDTH = 240
const CHART_HEIGHT = 100
const HOUR_WIDTH = CHART_WIDTH / 24

/**
 * "Security Activity" — an hourly-volume line/area chart for today, built
 * entirely from real audit rows: a single GET /v1/audit-logs?limit=100
 * (the backend's own maximum — see dto.AuditLogQuery.Validate), filtered
 * client-side to events whose occurred_at falls on the visitor's local
 * calendar date, then bucketed by local hour. This is a *separate* query
 * from the limit:5 one PrimaryMetrics/SecurityStatusPanel/
 * SecurityActivityTimeline share — a genuinely different question
 * ("volume over today," not "the 5 most recent rows"), so it's a second
 * real request rather than reusing that cache entry.
 *
 * The line connects real per-hour counts with straight segments —
 * deliberately not a smoothed/interpolated curve, which on real (possibly
 * spiky, possibly sparse) data can visually imply values between two
 * known points that were never actually measured. There is no
 * time-series/aggregation endpoint on this backend to ask for
 * pre-bucketed counts directly, so every point here is a real count of
 * real fetched rows. If fewer than 100 total events exist, this chart may
 * not actually cover the *entire* day (the oldest fetched row could
 * already be from partway through today) — in that case the chart is
 * captioned as showing only the events available rather than silently
 * implying full-day coverage it can't back up.
 */
export function SecurityActivityChart() {
  const { data, isLoading, isError, refetch, isRefetching } = useAuditLogs({ limit: 100 })
  const [hoveredHour, setHoveredHour] = useState<number | null>(null)

  const { hourCounts, todayCount, maxCount, mayBeIncomplete } = useMemo(() => {
    const counts = new Array<number>(24).fill(0)
    if (!data) return { hourCounts: counts, todayCount: 0, maxCount: 0, mayBeIncomplete: false }

    const now = new Date()
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate())

    let count = 0
    for (const event of data.data) {
      const occurred = new Date(event.occurred_at)
      if (occurred >= todayStart) {
        counts[occurred.getHours()] += 1
        count += 1
      }
    }
    // If the oldest row this 100-row fetch returned is itself from today,
    // there may be earlier events today this fetch never reached.
    const oldest = data.data[data.data.length - 1]
    const incomplete = data.data.length === 100 && oldest && new Date(oldest.occurred_at) >= todayStart

    return { hourCounts: counts, todayCount: count, maxCount: Math.max(...counts, 1), mayBeIncomplete: incomplete }
  }, [data])

  const points = useMemo(
    () =>
      hourCounts.map((count, hour) => ({
        hour,
        count,
        x: hour * HOUR_WIDTH + HOUR_WIDTH / 2,
        y: CHART_HEIGHT - (count / maxCount) * (CHART_HEIGHT - 12),
      })),
    [hourCounts, maxCount],
  )

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ")
  const areaPath = `M ${points[0].x} ${CHART_HEIGHT} ${points
    .map((p) => `L ${p.x} ${p.y}`)
    .join(" ")} L ${points[points.length - 1].x} ${CHART_HEIGHT} Z`

  return (
    <Card className="flex-1">
      <CardHeader className="flex flex-row items-baseline justify-between gap-4">
        <div>
          <CardTitle>Security Activity</CardTitle>
          <p className="mt-0.5 text-sm text-muted-foreground">Audit event volume today, by hour.</p>
        </div>
        {!isLoading && !isError && todayCount > 0 && (
          <span className="shrink-0 text-xs text-muted-foreground">Last 24 hours</span>
        )}
      </CardHeader>
      <CardContent>
        {isLoading && <Skeleton className="h-24 w-full" />}

        {!isLoading && isError && (
          <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-8 text-center">
            <p className="text-sm text-muted-foreground">Unable to load security activity.</p>
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isRefetching}>
              <RefreshCw className={cn("size-3.5", isRefetching && "animate-spin")} />
              {isRefetching ? "Retrying…" : "Retry"}
            </Button>
          </div>
        )}

        {!isLoading && !isError && todayCount === 0 && (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-border py-8 text-center text-sm text-muted-foreground">
            <BarChart3 className="size-5" strokeWidth={1.5} aria-hidden="true" />
            <p>No security activity recorded today.</p>
          </div>
        )}

        {!isLoading && !isError && todayCount > 0 && (
          <div className="flex flex-col gap-1.5">
            <p className="text-2xl font-semibold tracking-tight text-foreground">{todayCount.toLocaleString()}</p>
            <p className="-mt-1 text-xs text-muted-foreground">
              event{todayCount === 1 ? "" : "s"} today
              {mayBeIncomplete && " (earlier events today may not be shown)"}
            </p>

            <div className="relative mt-1 h-20">
              <svg
                viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`}
                preserveAspectRatio="none"
                className="h-full w-full overflow-visible"
                role="img"
                aria-label={`${todayCount} audit event${todayCount === 1 ? "" : "s"} recorded today, by hour`}
              >
                <defs>
                  <linearGradient id="kanz-activity-fill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--kanz-primary)" stopOpacity="0.25" />
                    <stop offset="100%" stopColor="var(--kanz-primary)" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <path d={areaPath} fill="url(#kanz-activity-fill)" />
                <path d={linePath} stroke="var(--kanz-primary)" strokeWidth="1.5" fill="none" vectorEffect="non-scaling-stroke" />
                {hoveredHour !== null && (
                  <>
                    <line
                      x1={points[hoveredHour].x}
                      y1="0"
                      x2={points[hoveredHour].x}
                      y2={CHART_HEIGHT}
                      stroke="var(--kanz-border)"
                      strokeWidth="1"
                      vectorEffect="non-scaling-stroke"
                    />
                    <circle
                      cx={points[hoveredHour].x}
                      cy={points[hoveredHour].y}
                      r="2.5"
                      fill="var(--kanz-primary-glow)"
                      stroke="var(--kanz-bg)"
                      strokeWidth="1"
                      vectorEffect="non-scaling-stroke"
                    />
                  </>
                )}
              </svg>

              {/* Invisible per-hour hit targets, aligned to the same 24
                  equal-width columns the chart geometry above uses —
                  keyboard-focusable too, so the tooltip isn't hover-only. */}
              <div className="absolute inset-0 flex" onMouseLeave={() => setHoveredHour(null)}>
                {hourCounts.map((count, hour) => (
                  <button
                    key={hour}
                    type="button"
                    className="flex-1 focus-visible:outline-none"
                    onMouseEnter={() => setHoveredHour(hour)}
                    onFocus={() => setHoveredHour(hour)}
                    onBlur={() => setHoveredHour(null)}
                    aria-label={`${String(hour).padStart(2, "0")}:00 — ${count} event${count === 1 ? "" : "s"}`}
                  />
                ))}
              </div>

              {hoveredHour !== null && (
                <div
                  className="pointer-events-none absolute bottom-full z-10 mb-1.5 -translate-x-1/2 rounded-md border border-border bg-kanz-surface-elevated px-2 py-1 text-center whitespace-nowrap shadow-[var(--kanz-shadow-sm)]"
                  style={{ left: `${((hoveredHour + 0.5) / 24) * 100}%` }}
                >
                  <p className="text-xs font-medium text-foreground">{String(hoveredHour).padStart(2, "0")}:00</p>
                  <p className="text-[0.65rem] text-muted-foreground">
                    {hourCounts[hoveredHour]} event{hourCounts[hoveredHour] === 1 ? "" : "s"}
                  </p>
                </div>
              )}
            </div>

            <div className="flex">
              {hourCounts.map((_, hour) => (
                <div key={hour} className="flex-1 text-center text-[0.6rem] text-muted-foreground">
                  {LABELED_HOURS.has(hour) ? String(hour).padStart(2, "0") : ""}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
