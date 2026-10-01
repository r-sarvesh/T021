'use client'

import { ShieldX, ScrollText } from 'lucide-react'
import { listAuditEvents } from '@/lib/api/client'
import { useAsync } from '@/lib/use-async'
import { useAuth } from '@/lib/auth/auth-provider'
import { ErrorState, TableSkeleton } from '@/components/data-states'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { formatDateTime } from '@/lib/format'
import type { AuditEvent } from '@/lib/api/types'

export function AuditLogView() {
  const { user, status } = useAuth()
  const isAdmin = status === 'authenticated' && user?.role === 'admin'

  const audit = useAsync(() => (isAdmin ? listAuditEvents('admin') : Promise.resolve([] as AuditEvent[])), [isAdmin])

  // Show loading while auth resolves (AppGuard handles redirect for unauthenticated)
  if (status === 'loading') {
    return (
      <Card>
        <CardContent className="p-4">
          <TableSkeleton rows={8} />
        </CardContent>
      </Card>
    )
  }

  // Non-admin defensive UI — AppGuard also blocks at route level, but this handles direct API 403
  if (!isAdmin) {
    return (
      <div className="flex flex-col items-center gap-4 py-16 text-center">
        <div className="flex size-14 items-center justify-center rounded-full bg-critical/15 text-critical">
          <ShieldX className="size-7" aria-hidden="true" />
        </div>
        <div className="flex flex-col gap-1.5">
          <h2 className="text-lg font-semibold tracking-tight">Access restricted</h2>
          <p className="max-w-md text-sm text-muted-foreground">
            You do not have permission to access the audit log. This view is restricted to administrators.
          </p>
        </div>
      </div>
    )
  }

  if (audit.loading) {
    return (
      <Card>
        <CardContent className="p-4">
          <TableSkeleton rows={8} />
        </CardContent>
      </Card>
    )
  }

  if (audit.error) {
    // Handle 403 as restricted rather than generic error
    const msg = audit.error.message || ''
    const isRestricted =
      msg.toLowerCase().includes('permission') ||
      msg.toLowerCase().includes('unauthorized') ||
      msg.toLowerCase().includes('access')
    if (isRestricted) {
      return (
        <div className="flex flex-col items-center gap-4 py-16 text-center">
          <div className="flex size-14 items-center justify-center rounded-full bg-critical/15 text-critical">
            <ShieldX className="size-7" aria-hidden="true" />
          </div>
          <div className="flex flex-col gap-1.5">
            <h2 className="text-lg font-semibold tracking-tight">Access restricted</h2>
            <p className="max-w-md text-sm text-muted-foreground">{msg}</p>
          </div>
        </div>
      )
    }
    return <ErrorState message={msg} onRetry={audit.reload} />
  }

  const events = audit.data ?? []

  if (events.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-2 py-16 text-center">
          <ScrollText className="size-8 text-muted-foreground" aria-hidden="true" />
          <p className="text-sm font-medium">No audit events</p>
          <p className="max-w-sm text-sm text-muted-foreground">
            Audit events will appear here once actions such as logins, imports, or report exports occur.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Actor</th>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Target</th>
                <th className="px-4 py-3 font-medium">Result</th>
                <th className="px-4 py-3 font-medium">IP</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="border-b border-border/60 last:border-0 hover:bg-muted/30">
                  <td className="px-4 py-3 font-mono text-xs tabular-nums text-muted-foreground">
                    {formatDateTime(e.timestamp)}
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-medium">{e.user}</span>
                    <span className="ml-2 text-xs text-muted-foreground">{e.role}</span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{e.action}</td>
                  <td className="px-4 py-3 text-muted-foreground">{e.target}</td>
                  <td className="px-4 py-3">
                    <Badge variant={e.result === 'success' ? 'secondary' : 'destructive'}>{e.result}</Badge>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{e.ip ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}
