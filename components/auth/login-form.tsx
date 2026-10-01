'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Eye, EyeOff, Lock, ShieldAlert, Radar } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Spinner } from '@/components/ui/spinner'
import { useAuth } from '@/lib/auth/auth-provider'
import { isApiError } from '@/lib/api/types'

export function LoginForm() {
  const { signIn, status } = useAuth()
  const router = useRouter()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<{ title: string; message: string } | null>(null)

  useEffect(() => {
    if (status === 'authenticated') router.replace('/dashboard')
  }, [status, router])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (submitting) return
    setError(null)
    setSubmitting(true)
    try {
      await signIn(username, password)
      router.replace('/dashboard')
    } catch (err) {
      if (isApiError(err)) {
        setError({
          title: err.code === 'account_locked' ? 'Account locked' : 'Sign-in failed',
          message: err.message,
        })
      } else {
        setError({
          title: 'Unable to sign in',
          message: 'Unable to connect to the assessment service. Please try again.',
        })
      }
      setSubmitting(false)
    }
  }

  return (
    <div className="grid min-h-svh lg:grid-cols-2">
      {/* Brand / context panel */}
      <div className="relative hidden flex-col justify-between overflow-hidden border-r border-border bg-card p-10 lg:flex">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage:
              'radial-gradient(circle at 1px 1px, var(--foreground) 1px, transparent 0)',
            backgroundSize: '22px 22px',
          }}
          aria-hidden="true"
        />
        <div className="relative flex items-center gap-2.5">
          <div className="flex size-9 items-center justify-center rounded-md bg-primary/15 text-primary">
            <Radar className="size-5" aria-hidden="true" />
          </div>
          <div className="leading-tight">
            <p className="font-semibold tracking-tight">Cyber Health Assess</p>
            <p className="text-xs text-muted-foreground">Vulnerability Assessment Platform</p>
          </div>
        </div>

        <div className="relative flex flex-col gap-6">
          <h1 className="max-w-sm text-balance text-3xl font-semibold leading-tight tracking-tight">
            Evidence-backed cybersecurity assessment for security operations.
          </h1>
          <ul className="flex flex-col gap-3 text-sm text-muted-foreground">
            <li className="flex items-start gap-2.5">
              <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-primary" aria-hidden="true" />
              Import Nmap scans and monitor backend processing end to end.
            </li>
            <li className="flex items-start gap-2.5">
              <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-primary" aria-hidden="true" />
              Every finding is traced to its CVE and CIS evidence — or clearly marked unverified.
            </li>
            <li className="flex items-start gap-2.5">
              <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-primary" aria-hidden="true" />
              Compare host risk and export professional security reports.
            </li>
          </ul>
        </div>

        <p className="relative text-xs text-muted-foreground">
          Restricted access. Authorized security personnel only. All activity is logged.
        </p>
      </div>

      {/* Sign-in panel */}
      <div className="flex items-center justify-center p-6 sm:p-10">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <div className="flex size-9 items-center justify-center rounded-md bg-primary/15 text-primary">
              <Radar className="size-5" aria-hidden="true" />
            </div>
            <p className="font-semibold tracking-tight">Cyber Health Assess</p>
          </div>

          <div className="mb-6 flex flex-col gap-1.5">
            <div className="inline-flex w-fit items-center gap-1.5 rounded-md border border-border bg-muted/40 px-2 py-0.5 text-xs font-medium text-muted-foreground">
              <Lock className="size-3" aria-hidden="true" />
              Restricted access
            </div>
            <h2 className="text-2xl font-semibold tracking-tight">Sign in</h2>
            <p className="text-sm text-muted-foreground">
              Enter your credentials to access the assessment platform.
            </p>
          </div>

          {error && (
            <Alert variant="destructive" className="mb-4">
              <ShieldAlert />
              <AlertTitle>{error.title}</AlertTitle>
              <AlertDescription>{error.message}</AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleSubmit} noValidate>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="username">Username</FieldLabel>
                <Input
                  id="username"
                  name="username"
                  autoComplete="username"
                  autoFocus
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. analyst"
                  disabled={submitting}
                />
              </Field>

              <Field>
                <FieldLabel htmlFor="password">Password</FieldLabel>
                <div className="relative">
                  <Input
                    id="password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    disabled={submitting}
                    className="pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((s) => !s)}
                    className="absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground transition-colors hover:text-foreground focus-visible:text-foreground focus-visible:outline-none"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    tabIndex={0}
                  >
                    {showPassword ? (
                      <EyeOff className="size-4" aria-hidden="true" />
                    ) : (
                      <Eye className="size-4" aria-hidden="true" />
                    )}
                  </button>
                </div>
              </Field>

              <Button type="submit" size="lg" className="w-full" disabled={submitting}>
                {submitting && <Spinner data-icon="inline-start" />}
                {submitting ? 'Signing in…' : 'Sign in'}
              </Button>
            </FieldGroup>
          </form>

          <div className="mt-6 rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
            <p className="mb-1 font-medium text-foreground">Demo credentials</p>
            <p className="font-mono">admin / admin123 — Administrator</p>
            <p className="font-mono">analyst / analyst123 — Security Analyst</p>
          </div>
        </div>
      </div>
    </div>
  )
}
