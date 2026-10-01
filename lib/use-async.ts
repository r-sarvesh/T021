'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { isApiError } from '@/lib/api/types'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: { message: string } | null
  reload: () => void
}

/**
 * Minimal data-fetching hook for the API adapter. Handles loading/error state
 * and re-runs when `deps` change. Fetches happen through the adapter only —
 * components never call the backend or fixtures directly.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<{ message: string } | null>(null)
  const [nonce, setNonce] = useState(0)
  const fnRef = useRef(fn)
  fnRef.current = fn

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  useEffect(() => {
    let active = true
    setLoading(true)
    setError(null)
    fnRef
      .current()
      .then((result) => {
        if (active) {
          setData(result)
          setLoading(false)
        }
      })
      .catch((err) => {
        if (active) {
          setError({
            message: isApiError(err)
              ? err.message
              : 'Unable to connect to the assessment service. Please try again.',
          })
          setLoading(false)
        }
      })
    return () => {
      active = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce])

  return { data, loading, error, reload }
}
