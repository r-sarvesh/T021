import { CheckCircle2, Clock, Loader2, XCircle } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ScanStatus } from '@/lib/api/types'

const config: Record<
  ScanStatus,
  { label: string; icon: typeof Clock; className: string; spin?: boolean }
> = {
  completed: {
    label: 'Completed',
    icon: CheckCircle2,
    className: 'bg-verified/15 text-verified border-verified/30',
  },
  processing: {
    label: 'Processing',
    icon: Loader2,
    className: 'bg-primary/15 text-primary border-primary/30',
    spin: true,
  },
  queued: {
    label: 'Queued',
    icon: Clock,
    className: 'bg-muted/50 text-muted-foreground border-border',
  },
  failed: {
    label: 'Failed',
    icon: XCircle,
    className: 'bg-critical/15 text-critical border-critical/30',
  },
}

export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus
  className?: string
}) {
  const { label, icon: Icon, className: tone, spin } = config[status]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium',
        tone,
        className,
      )}
    >
      <Icon className={cn('size-3.5', spin && 'animate-spin')} aria-hidden="true" />
      {label}
    </span>
  )
}
