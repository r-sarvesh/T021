import { notFound } from 'next/navigation'
import { PageShell } from '@/components/shell/page-shell'
import { ScanDetailView } from '@/components/scans/scan-detail-view'

export default async function ScanDetailPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await params
  if (!scanId) notFound()
  return (
    <PageShell title={`Scan ${scanId}`} crumbs={[{ label: 'Scans', href: '/scans' }, { label: scanId }]}>
      <ScanDetailView scanId={scanId} />
    </PageShell>
  )
}
