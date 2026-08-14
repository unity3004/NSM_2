import type { LucideIcon } from "lucide-react"
import { Link } from "react-router-dom"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

/**
 * One of the four primary metric tiles (Secrets/Dynamic Leases/Policies/
 * Audit Events). Every count this renders comes from the caller's own
 * real query state — this component has no data-fetching of its own and
 * never invents a number: `value === null` always means "not a real
 * count yet" (loading, errored, or the query itself has no notion of a
 * total), and is the only thing that ever produces the empty/unavailable
 * copy instead of a digit.
 *
 * `possiblyTruncated` mirrors the existing ResourceOverviewCard
 * convention: true only when the underlying page came back exactly as
 * long as its own page.limit, the one honest signal available that more
 * rows might exist beyond a fixed-size, non-paginating list endpoint.
 */
interface MetricCardProps {
  icon: LucideIcon
  label: string
  description: string
  href: string
  isLoading: boolean
  isError: boolean
  value: number | null
  possiblyTruncated?: boolean
  emptyLabel: string
}

export function MetricCard({
  icon: Icon,
  label,
  description,
  href,
  isLoading,
  isError,
  value,
  possiblyTruncated = false,
  emptyLabel,
}: MetricCardProps) {
  return (
    <Link
      to={href}
      className={cn(
        "group flex flex-col gap-3 rounded-xl border border-border bg-card p-4 ring-1 ring-foreground/10",
        "transition-[transform,border-color,box-shadow] duration-[var(--kanz-transition-base)]",
        "hover:-translate-y-0.5 hover:border-kanz-primary/40 hover:shadow-[var(--kanz-glow-sm)]",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kanz-primary/50",
      )}
    >
      <div className="flex items-center justify-between">
        <span className="flex size-9 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
          <Icon className="size-4.5" strokeWidth={1.75} aria-hidden="true" />
        </span>
        <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{label}</span>
      </div>

      <div className="flex flex-col gap-0.5">
        {isLoading && <Skeleton className="h-8 w-16" />}

        {!isLoading && isError && (
          <span className="text-sm font-medium text-muted-foreground">Unavailable</span>
        )}

        {!isLoading && !isError && value === null && (
          <span className="text-sm font-medium text-muted-foreground">No data available</span>
        )}

        {!isLoading && !isError && value === 0 && (
          <span className="text-sm font-medium text-muted-foreground">{emptyLabel}</span>
        )}

        {!isLoading && !isError && value !== null && value !== 0 && (
          <>
            <span className="font-mono text-3xl font-semibold tracking-tight text-foreground">
              {value.toLocaleString()}
              {possiblyTruncated && "+"}
            </span>
            <span className="text-xs text-muted-foreground">{description}</span>
          </>
        )}
      </div>
    </Link>
  )
}
