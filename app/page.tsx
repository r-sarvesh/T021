'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Radar } from 'lucide-react'
import { useAuth } from '@/lib/auth/auth-provider'

export default function RootPage() {
  const { status } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (status === 'authenticated') router.replace('/dashboard')
    else if (status === 'unauthenticated') router.replace('/login')
  }, [status, router])

  return (
    <div className="flex min-h-svh items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-3 text-muted-foreground">
        <Radar className="size-6 animate-pulse text-primary" aria-hidden="true" />
        <p className="text-sm">Loading Cyber Health Assess…</p>
      </div>
    </div>
  )
}
