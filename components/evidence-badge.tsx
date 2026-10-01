import { ShieldCheck, ShieldQuestion } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { EvidenceStatus } from '@/lib/api/types'

/**
 * Evidence indicator — the platform's core trust signal. Evidence-backed and
 * unverified findings must never look equivalent, so the two states use
 * distinct color, icon, and label treatments.
 */
export function EvidenceBadge({
  status,
  className,
}: {
  status: EvidenceStatus
  className?: string
}) {
  if (status === 'backed') {
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 rounded-md border border-verified/30 bg-verified/15 px-2 py-0.5 text-xs font-medium text-verified',
          className,
        )}
      >
        <ShieldCheck className="size-3.5" aria-hidden="true" />
        Evidence-backed
      </span>
    )
  }
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border border-border bg-muted/40 px-2 py-0.5 text-xs font-medium text-muted-foreground',
        className,
      )}
    >
      <ShieldQuestion className="size-3.5" aria-hidden="true" />
      No evidence
    </span>
  )
}
