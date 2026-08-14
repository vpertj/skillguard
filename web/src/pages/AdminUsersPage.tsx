import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntApp, Button, Card, Form, InputNumber, Modal, Select, Table, Tag, Typography } from 'antd'
import { EditOutlined } from '@ant-design/icons'
import { adminApi } from '../api/client'
import type { AdminUser } from '../api/types'

interface EditForm {
  quota_audits: number
  quota_llm_reviews: number
  role: 'user' | 'admin'
}

export default function AdminUsersPage() {
  const { message } = AntApp.useApp()
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<AdminUser | null>(null)
  const [form] = Form.useForm<EditForm>()

  const { data, isLoading } = useQuery({ queryKey: ['admin-users'], queryFn: adminApi.listUsers })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: number; body: EditForm }) => adminApi.updateUser(id, body),
    onSuccess: (_d, vars) => {
      message.success(`已更新用户 ${vars.id} 的配额与角色`)
      setEditing(null)
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
    },
    onError: (e) => message.error(e instanceof Error ? e.message : '更新失败'),
  })

  const openEdit = (u: AdminUser) => {
    setEditing(u)
    form.setFieldsValue({ quota_audits: u.quota_audits, quota_llm_reviews: u.quota_llm_reviews, role: u.role === 'admin' ? 'admin' : 'user' })
  }

  const columns = [
    { title: 'ID', dataIndex: 'id', width: 60 },
    { title: '邮箱', dataIndex: 'email' },
    {
      title: '角色',
      dataIndex: 'role',
      width: 90,
      render: (v: string) => (v === 'admin' ? <Tag color="gold">管理员</Tag> : <Tag>用户</Tag>),
    },
    { title: '静态审计配额', dataIndex: 'quota_audits', width: 120 },
    { title: '深度分析配额', dataIndex: 'quota_llm_reviews', width: 120 },
    { title: '注册时间', dataIndex: 'created_at', width: 170 },
    {
      title: '操作',
      width: 90,
      render: (_: unknown, record: AdminUser) => (
        <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(record)}>
          编辑
        </Button>
      ),
    },
  ]

  return (
    <div>
      <Typography.Title level={4}>用户管理</Typography.Title>
      <Card>
        <Typography.Paragraph type="secondary">
          管理员可为用户分配 / 调整配额（静态审计、深度分析）与角色。
        </Typography.Paragraph>
        <Table<AdminUser>
          rowKey="id"
          loading={isLoading}
          dataSource={data?.users ?? []}
          columns={columns}
          pagination={{ pageSize: 20 }}
          locale={{ emptyText: '暂无用户' }}
        />
      </Card>

      <Modal
        title={editing ? `编辑用户：${editing.email}` : ''}
        open={!!editing}
        onCancel={() => setEditing(null)}
        onOk={() => form.submit()}
        confirmLoading={updateMut.isPending}
        okText="保存"
      >
        <Form form={form} layout="vertical" onFinish={(v: EditForm) => editing && updateMut.mutate({ id: editing.id, body: v })}>
          <Form.Item name="quota_audits" label="静态审计配额（次/月）" rules={[{ required: true }]}>
            <InputNumber min={0} max={100000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="quota_llm_reviews" label="深度分析配额（次/月）" rules={[{ required: true }]}>
            <InputNumber min={0} max={100000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="role" label="角色" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'user', label: '普通用户' },
                { value: 'admin', label: '管理员' },
              ]}
            />
          </Form.Item>
          <Typography.Text type="warning" style={{ fontSize: 12 }}>
            角色变更后，该用户需重新登录才能生效。
          </Typography.Text>
        </Form>
      </Modal>
    </div>
  )
}
