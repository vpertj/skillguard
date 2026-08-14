// 认证状态：token + 用户信息，localStorage 持久化
import { create } from 'zustand'
import { getToken, setToken } from '../api/client'
import type { User } from '../api/types'

const USER_KEY = 'sg_user'

function loadUser(): User | null {
  try {
    const raw = localStorage.getItem(USER_KEY)
    return raw ? (JSON.parse(raw) as User) : null
  } catch {
    return null
  }
}

interface AuthState {
  token: string | null
  user: User | null
  setAuth: (token: string, user: User) => void
  logout: () => void
}

export const useAuth = create<AuthState>((set) => ({
  token: getToken(),
  user: loadUser(),
  setAuth: (token, user) => {
    setToken(token)
    localStorage.setItem(USER_KEY, JSON.stringify(user))
    set({ token, user })
  },
  logout: () => {
    setToken(null)
    localStorage.removeItem(USER_KEY)
    set({ token: null, user: null })
  },
}))
