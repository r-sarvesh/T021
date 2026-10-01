import type { Metadata } from 'next'
import { PageShell } from '@/components/shell/page-shell'
import { ImportView } from '@/components/import/import-view'

export const metadata: Metadata = {
  title: 'Import Nmap Scan',
}

export default function ImportPage() {
  return (
    <PageShell title="Import scan" crumbs={[{ label: 'Scans', href: '/scans' }, { label: 'Import' }]}>
      <ImportView />
    </PageShell>
  )
}
