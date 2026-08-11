import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const relativeTimeFormatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" })
const relativeTimeUnits: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 60 * 60 * 24 * 365],
  ["month", 60 * 60 * 24 * 30],
  ["week", 60 * 60 * 24 * 7],
  ["day", 60 * 60 * 24],
  ["hour", 60 * 60],
  ["minute", 60],
]

/** "2 minutes ago", "1 hour ago", "3 days ago" — built on the standard
 * Intl.RelativeTimeFormat API, no date library dependency. No existing
 * formatter of this kind exists elsewhere in this app (every other date
 * display uses toLocaleString/toLocaleDateString directly); this one
 * exists because the Secrets list specifically benefits from "how fresh is
 * this" at a glance the way an absolute timestamp doesn't communicate as
 * quickly in a dense table. Falls back to a plain locale date once a
 * timestamp is more than a year old, where relative phrasing stops being
 * useful. */
export function formatRelativeTime(iso: string): string {
  const then = new Date(iso).getTime()
  const diffSeconds = Math.round((then - Date.now()) / 1000)
  const absSeconds = Math.abs(diffSeconds)

  if (absSeconds < 60) return "just now"

  for (const [unit, secondsInUnit] of relativeTimeUnits) {
    if (absSeconds >= secondsInUnit) {
      const value = Math.round(diffSeconds / secondsInUnit)
      return relativeTimeFormatter.format(value, unit)
    }
  }
  return new Date(iso).toLocaleDateString()
}
