// fetch 封装：自动带 Bearer token、JSON 解析、统一错误
import type { AdminUserListResp, AuthResp, AuditListResp, AuditResp, CreateKeyResp, DeepSeekSettings, KeyListResp, UsageResp } from './types'

const TOKEN_KEY = 'sg_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

interface RequestOpts {
  method?: string
  body?: unknown
  form?: FormData
}

export async function api<T>(path: string, opts: RequestOpts = {}): Promise<T> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = 'Bearer ' + token

  let body: BodyInit | undefined
  if (opts.form) {
    body = opts.form
  } else if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }

  let res: Response
  try {
    res = await fetch('/v1' + path, { method: opts.method ?? 'GET', headers, body })
  } catch {
    throw new ApiError(0, '无法连接服务器，请确认后端已启动')
  }
  if (!res.ok) {
    let msg = `请求失败 (${res.status})`
    try {
      const d = await res.json()
      if (d?.error) msg = d.error
    } catch {
      /* 忽略解析失败 */
    }
    throw new ApiError(res.status, msg)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

// —— 业务接口 ——
export const authApi = {
  register: (email: string, password: string) => api<AuthResp>('/auth/register', { method: 'POST', body: { email, password } }),
  login: (email: string, password: string) => api<AuthResp>('/auth/login', { method: 'POST', body: { email, password } }),
}

export const keyApi = {
  create: (name: string) => api<CreateKeyResp>('/keys', { method: 'POST', body: { name } }),
  list: () => api<KeyListResp>('/keys'),
  revoke: (id: number) => api<void>(`/keys/${id}`, { method: 'DELETE' }),
}

export const auditApi = {
  upload: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return api<AuditResp>('/audit', { method: 'POST', form })
  },
  // 付费档：静态 + LLM 语义分析（按 llm_review 计费）
  deep: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return api<AuditResp>('/audit/deep', { method: 'POST', form })
  },
  history: () => api<AuditListResp>('/audits'),
}

export const usageApi = {
  get: () => api<UsageResp>('/usage'),
}

// —— 管理员接口 ——
export const adminApi = {
  listUsers: () => api<AdminUserListResp>('/admin/users?limit=200'),
  updateUser: (id: number, body: { quota_audits?: number; quota_llm_reviews?: number; role?: string }) =>
    api<{ ok: boolean }>(`/admin/users/${id}`, { method: 'PUT', body }),
  getDeepSeek: () => api<DeepSeekSettings>('/admin/settings/deepseek'),
  putDeepSeek: (api_key: string) => api<{ ok: boolean; configured: boolean }>('/admin/settings/deepseek', { method: 'PUT', body: { api_key } }),
}
