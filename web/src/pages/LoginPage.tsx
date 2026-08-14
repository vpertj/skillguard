import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { App as AntApp, Button, Card, Form, Input, Tabs, Typography } from 'antd'
import { LockOutlined, MailOutlined } from '@ant-design/icons'
import { authApi } from '../api/client'
import { useAuth } from '../stores/auth'

export default function LoginPage() {
  const { message } = AntApp.useApp()
  const navigate = useNavigate()
  const setAuth = useAuth((s) => s.setAuth)
  const [tab, setTab] = useState('login')
  const [loading, setLoading] = useState(false)

  const submit = async (values: { email: string; password: string }) => {
    setLoading(true)
    try {
      const resp = tab === 'login' ? await authApi.login(values.email, values.password) : await authApi.register(values.email, values.password)
      setAuth(resp.token, resp.user)
      message.success(tab === 'login' ? '登录成功' : '注册成功')
      navigate('/', { replace: true })
    } catch (e) {
      message.error(e instanceof Error ? e.message : '操作失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f5f7fa' }}>
      <Card style={{ width: 380 }}>
        <Typography.Title level={3} style={{ textAlign: 'center', marginBottom: 4 }}>
          SkillGuard
        </Typography.Title>
        <Typography.Paragraph type="secondary" style={{ textAlign: 'center', marginBottom: 20 }}>
          技能安全审计平台
        </Typography.Paragraph>
        <Tabs
          activeKey={tab}
          onChange={setTab}
          centered
          items={[
            { key: 'login', label: '登录' },
            { key: 'register', label: '注册' },
          ]}
        />
        <Form onFinish={submit} layout="vertical" requiredMark={false}>
          <Form.Item name="email" rules={[{ required: true, message: '请输入邮箱' }, { type: 'email', message: '邮箱格式不正确' }]}>
            <Input prefix={<MailOutlined />} placeholder="邮箱" size="large" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }, { min: 8, message: '密码至少 8 位' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码（至少 8 位）" size="large" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block size="large" loading={loading}>
            {tab === 'login' ? '登 录' : '注 册'}
          </Button>
        </Form>
      </Card>
    </div>
  )
}
