import { useEffect, useState } from "react"

export interface Countdown {
  remainingMs: number
  expired: boolean
  /** "Expires in 08m 42s" under an hour, "Expires in 1h 12m" at an hour
   * or more, "Expired" once past the real expires_at timestamp. */
  label: string
}

function formatRemaining(ms: number): string {
  if (ms <= 0) return "Expired"
  const totalSeconds = Math.floor(ms / 1000)
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  if (hours >= 1) return `Expires in ${hours}h ${minutes}m`
  return `Expires in ${String(minutes).padStart(2, "0")}m ${String(seconds).padStart(2, "0")}s`
}

/**
 * A client-side-only ticking countdown to a real, server-issued
 * `expiresAt` timestamp — pure presentation. Every second it recomputes
 * `Date.now()` vs. that real timestamp; it never writes anything, never
 * triggers a network request, and the server's own record of the lease
 * remains the sole authority on whether it's actually still valid. The
 * interval clears itself the moment the countdown reaches zero (checked
 * inside the tick, not just on unmount) rather than continuing to fire
 * forever on an already-expired lease, and `active=false` (a lease that's
 * already revoked/expired server-side) skips starting one at all.
 */
export function useCountdown(expiresAt: string, active: boolean): Countdown {
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    if (!active) return
    const target = new Date(expiresAt).getTime()
    if (target <= Date.now()) return
    const interval = setInterval(() => {
      const nowMs = Date.now()
      setNow(nowMs)
      if (nowMs >= target) clearInterval(interval)
    }, 1000)
    return () => clearInterval(interval)
  }, [expiresAt, active])

  const remainingMs = new Date(expiresAt).getTime() - now
  return { remainingMs, expired: remainingMs <= 0, label: formatRemaining(remainingMs) }
}
