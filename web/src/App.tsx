import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './stores/auth'
import AppLayout from './components/AppLayout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import AuditPage from './pages/AuditPage'
import KeysPage from './pages/KeysPage'
import HistoryPage from './pages/HistoryPage'
import AdminUsersPage from './pages/AdminUsersPage'
import AdminSettingsPage from './pages/AdminSettingsPage'

// 路由守卫：未登录跳转登录页
function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = useAuth((s) => s.token)
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

// 管理员守卫：普通用户访问管理页跳回首页
function RequireAdmin({ children }: { children: React.ReactNode }) {
  const user = useAuth((s) => s.user)
  if (user?.role !== 'admin') return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/keys" element={<KeysPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route
          path="/admin/users"
          element={
            <RequireAdmin>
              <AdminUsersPage />
            </RequireAdmin>
          }
        />
        <Route
          path="/admin/settings"
          element={
            <RequireAdmin>
              <AdminSettingsPage />
            </RequireAdmin>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
