'use client'

/**
 * Client-side session holder. It stores the session returned by the backend
 * (via the API adapter) and exposes the current user + role to the UI so
 * navigation and routes can adapt. The backend remains the authority for
 * authentication and authorization — this context only reflects it.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import { login as apiLogin, logout as apiLogout } from '@/lib/api/client'
import type { User } from '@/lib/api/types'

type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated'

interface AuthContextValue {
  user: User | null
  status: AuthStatus
  signIn: (username: string, password: string) => Promise<User>
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

const STORAGE_KEY = 'cha.session'

interface StoredSession {
  user: User
  token: string
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [status, setStatus] = useState<AuthStatus>('loading')

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY)
      if (raw) {
        const parsed = JSON.parse(raw) as StoredSession
        setUser(parsed.user)
        setStatus('authenticated')
        return
      }
    } catch {
      // Corrupt session — fall through to unauthenticated.
    }
    setStatus('unauthenticated')
  }, [])

  const signIn = useCallback(async (username: string, password: string) => {
    const session = await apiLogin(username, password)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
    setUser(session.user)
    setStatus('authenticated')
    return session.user
  }, [])

  const signOut = useCallback(async () => {
    await apiLogout()
    localStorage.removeItem(STORAGE_KEY)
    setUser(null)
    setStatus('unauthenticated')
  }, [])

  const value = useMemo(
    () => ({ user, status, signIn, signOut }),
    [user, status, signIn, signOut],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}
