'use client'

import { useCallback, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  CheckCircle2,
  FileCode2,
  FileWarning,
  Loader2,
  ShieldCheck,
  UploadCloud,
  X,
} from 'lucide-react'
import { importScan, type ImportProgress } from '@/lib/api/client'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { ReportInlineView } from '@/components/import/report-inline-view'
import { cn } from '@/lib/utils'

type Phase = 'idle' | 'selected' | 'uploading' | 'completed' | 'error'

const IMPORT_STEPS = [
  'Uploading scan',
  'Processing hosts',
  'Analyzing findings',
  'Matching vulnerability evidence',
  'Preparing assessment',
]

export function ImportView() {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const [phase, setPhase] = useState<Phase>('idle')
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [progress, setProgress] = useState<ImportProgress | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [report, setReport] = useState<any>(null)

  const selectFile = useCallback((f: File | null) => {
    if (!f) return
    setError(null)
    setFile(f)
    setPhase('selected')
  }, [])

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragging(false)
      selectFile(e.dataTransfer.files?.[0] ?? null)
    },
    [selectFile],
  )

  const reset = useCallback(() => {
    setFile(null)
    setProgress(null)
    setError(null)
    setReport(null)
    setPhase('idle')
    if (inputRef.current) inputRef.current.value = ''
  }, [])

  const startImport = useCallback(async () => {
    if (!file) return
    setPhase('uploading')
    setError(null)
    setProgress({ step: IMPORT_STEPS[0], percent: 0 })
    try {
      const { scanId } = await importScan(file, setProgress)
      // Fetch full report for inline view (instead of navigating away)
      // The backend POST /report/upload returns report_id; GET /report/<id>/export returns full report JSON
      // For now, try to fetch report via scanId as reportId (they are same for live reports)
      // If importScan was for /api/scans/import, scanId is a scan; if it was /report/upload, scanId is report_id
      try {
        const token = typeof window !== 'undefined' ? localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token') : null
        const headers: Record<string, string> = {}
        if (token) headers['Authorization'] = `Bearer ${token}`
        // Try report export first (live report path), fallback to scan detail
        let reportRes = await fetch(`http://127.0.0.1:5000/report/${scanId}/export`, { headers })
        if (!reportRes.ok) {
          reportRes = await fetch(`http://127.0.0.1:5000/report/${scanId}`, { headers })
        }
        if (reportRes.ok) {
          const reportData = await reportRes.json()
          setReport(reportData)
          setPhase('completed')
          return
        }
      } catch (e) {
        // fallback to navigation if inline fetch fails
        console.warn('Inline report fetch failed, falling back to navigation', e)
      }
      router.push(`/scans/${scanId}`)
    } catch (err) {
      const message =
        err && typeof err === 'object' && 'message' in err
          ? String((err as { message: unknown }).message)
          : 'The import failed unexpectedly.'
      setError(message)
      setPhase('error')
    }
  }, [file, router])

  const currentStepIndex = progress
    ? IMPORT_STEPS.findIndex((s) => s === progress.step)
    : -1

  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-5">
        <div className="flex flex-col gap-1">
          <h2 className="text-lg font-semibold tracking-tight">Import Nmap scan</h2>
          <p className="text-sm text-muted-foreground">
            Upload an Nmap XML report. The backend parses the scan, assesses severity, and grounds
            each finding in evidence.
          </p>
        </div>
        {/* Upload / dropzone */}
        {(phase === 'idle' || phase === 'selected' || phase === 'error') && (
          <Card>
            <CardHeader>
              <CardTitle>Upload scan file</CardTitle>
              <CardDescription>
                Accepted format: Nmap XML output (<code className="font-mono text-xs">nmap -oX</code>
                ). Maximum one file per import.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div
                role="button"
                tabIndex={0}
                onClick={() => inputRef.current?.click()}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    inputRef.current?.click()
                  }
                }}
                onDragOver={(e) => {
                  e.preventDefault()
                  setDragging(true)
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                className={cn(
                  'flex cursor-pointer flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed border-border bg-muted/20 px-6 py-12 text-center transition-colors',
                  dragging && 'border-primary bg-primary/5',
                )}
                aria-label="Upload Nmap XML file"
              >
                <div className="flex size-12 items-center justify-center rounded-full bg-muted text-muted-foreground">
                  <UploadCloud className="size-6" aria-hidden="true" />
                </div>
                <div className="flex flex-col gap-1">
                  <p className="text-sm font-medium">
                    Drag &amp; drop your Nmap XML file, or click to browse
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Your file is transmitted to the assessment backend for processing.
                  </p>
                </div>
                <input
                  ref={inputRef}
                  type="file"
                  accept=".xml,text/xml,application/xml"
                  className="sr-only"
                  onChange={(e) => selectFile(e.target.files?.[0] ?? null)}
                />
              </div>

              {file && (
                <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-card px-3 py-2.5">
                  <div className="flex min-w-0 items-center gap-3">
                    <FileCode2 className="size-5 shrink-0 text-primary" aria-hidden="true" />
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{file.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {(file.size / 1024).toFixed(1)} KB
                      </p>
                    </div>
                  </div>
                  <Button variant="ghost" size="icon-sm" onClick={reset} aria-label="Remove file">
                    <X />
                  </Button>
                </div>
              )}

              {error && (
                <Alert variant="destructive">
                  <FileWarning />
                  <AlertTitle>Import failed</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <div className="flex items-center justify-end gap-2">
                <Button variant="outline" onClick={reset} disabled={!file}>
                  Clear
                </Button>
                <Button onClick={startImport} disabled={!file}>
                  <ShieldCheck data-icon="inline-start" />
                  Start assessment
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Processing */}
        {phase === 'uploading' && progress && (
          <Card>
            <CardHeader>
              <CardTitle>Processing assessment</CardTitle>
              <CardDescription>
                The backend is analyzing <span className="font-medium">{file?.name}</span>. This may
                take a moment.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-medium">{progress.step}</span>
                  <span className="font-mono text-muted-foreground tabular-nums">
                    {progress.percent}%
                  </span>
                </div>
                <Progress value={progress.percent} />
              </div>

              <ol className="flex flex-col gap-1">
                {IMPORT_STEPS.map((step, i) => {
                  const done = i < currentStepIndex
                  const active = i === currentStepIndex
                  return (
                    <li
                      key={step}
                      className={cn(
                        'flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm',
                        active && 'bg-muted/40',
                      )}
                    >
                      {done ? (
                        <CheckCircle2
                          className="size-4 text-[var(--sev-low)]"
                          aria-hidden="true"
                        />
                      ) : active ? (
                        <Loader2
                          className="size-4 animate-spin text-primary"
                          aria-hidden="true"
                        />
                      ) : (
                        <span
                          className="size-4 rounded-full border border-border"
                          aria-hidden="true"
                        />
                      )}
                      <span
                        className={cn(
                          done || active ? 'text-foreground' : 'text-muted-foreground',
                        )}
                      >
                        {step}
                      </span>
                    </li>
                  )
                })}
              </ol>
            </CardContent>
          </Card>
        )}

        {/* Completed — inline report (reuses report_view.html fields, stays on same page) */}
        {phase === 'completed' && report && (
          <ReportInlineView report={report} />
        )}
        {phase === 'completed' && !report && (
          <Card>
            <CardContent className="py-8 text-center">
              <p className="text-sm text-muted-foreground">Report ready — view in Scans.</p>
              <Button className="mt-3" onClick={reset}>Import another</Button>
            </CardContent>
          </Card>
        )}

        {/* Guidance */}
        <Alert>
          <ShieldCheck />
          <AlertTitle>How assessments are graded</AlertTitle>
          <AlertDescription>
            Severity, CVE matches, and risk scores are computed by the backend assessment engine.
            Findings shown as unverified could not be grounded in evidence and are flagged for
            analyst review rather than presented as confirmed.
          </AlertDescription>
        </Alert>
      </div>
  )
}
