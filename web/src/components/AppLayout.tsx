import { useMemo } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Layout, Menu, Dropdown, Button, Space, Typography } from 'antd'
import {
  DashboardOutlined,
  SafetyCertificateOutlined,
  KeyOutlined,
  HistoryOutlined,
  LogoutOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { useAuth } from '../stores/auth'

const { Sider, Content, Header } = Layout

export default function AppLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { user, logout } = useAuth()

  const selectedKey = useMemo(() => {
    const p = location.pathname
    if (p.startsWith('/audit')) return '/audit'
    if (p.startsWith('/keys')) return '/keys'
    if (p.startsWith('/history')) return '/history'
    return '/'
  }, [location.pathname])

  const menuItems = [
    { key: '/', icon: <DashboardOutlined />, label: '仪表盘' },
    { key: '/audit', icon: <SafetyCertificateOutlined />, label: '技能审计' },
    { key: '/keys', icon: <KeyOutlined />, label: 'API Keys' },
    { key: '/history', icon: <HistoryOutlined />, label: '审计历史' },
  ]

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider theme="dark" width={200}>
        <div style={{ height: 56, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 600, fontSize: 16 }}>
          SkillGuard
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            background: '#fff',
            padding: '0 24px',
            display: 'flex',
            justifyContent: 'flex-end',
            alignItems: 'center',
            borderBottom: '1px solid #f0f0f0',
          }}
        >
          <Dropdown
            menu={{
              items: [
                { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', onClick: () => { logout(); navigate('/login') } },
              ],
            }}
          >
            <Button type="text">
              <Space>
                <UserOutlined />
                <Typography.Text>{user?.email ?? '未登录'}</Typography.Text>
              </Space>
            </Button>
          </Dropdown>
        </Header>
        <Content style={{ margin: 24 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
