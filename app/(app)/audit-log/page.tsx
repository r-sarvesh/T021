import { PageShell } from '@/components/shell/page-shell'
import { AuditLogView } from '@/components/audit/audit-log-view'

export default function AuditLogPage() {
  return (
    <PageShell title="Audit Log">
      <div className="mb-4">
        <p className="text-sm text-muted-foreground">
          Admin-only view — backed by <span className="font-mono">GET /api/audit</span>. Server enforces role check.
        </p>
      </div>
      <AuditLogView />
    </PageShell>
  )
}
