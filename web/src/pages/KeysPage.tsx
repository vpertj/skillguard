import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntApp, Button, Card, Input, Modal, Popconfirm, Space, Table, Tag, Typography } from 'antd'
import { CopyOutlined, DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { keyApi } from '../api/client'
import type { APIKey } from '../api/types'

export default function KeysPage() {
  const { message } = AntApp.useApp()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)

  const { data, isLoading } = useQuery({ queryKey: ['keys'], queryFn: keyApi.list })

  const createMut = useMutation({
    mutationFn: () => keyApi.create(name.trim() || 'default'),
    onSuccess: (resp) => {
      setCreatedKey(resp.key)
      setCreateOpen(true)
      setName('')
      queryClient.invalidateQueries({ queryKey: ['keys'] })
    },
    onError: (e) => message.error(e instanceof Error ? e.message : '创建失败'),
  })

  const revokeMut = useMutation({
    mutationFn: (id: number) => keyApi.revoke(id),
    onSuccess: () => {
      message.success('已吊销')
      queryClient.invalidateQueries({ queryKey: ['keys'] })
    },
    onError: (e) => message.error(e instanceof Error ? e.message : '吊销失败'),
  })

  const columns = [
    { title: '名称', dataIndex: 'name', render: (v: string) => v || '-' },
    { title: '前缀', dataIndex: 'key_prefix', render: (v: string) => <Typography.Text code>{v}...</Typography.Text> },
    {
      title: '状态',
      dataIndex: 'revoked',
      render: (v: boolean) => (v ? <Tag color="default">已吊销</Tag> : <Tag color="green">生效中</Tag>),
    },
    { title: '创建时间', dataIndex: 'created_at' },
    {
      title: '操作',
      render: (_: unknown, record: APIKey) =>
        record.revoked ? null : (
          <Popconfirm title="吊销后该 Key 立即失效，确认？" onConfirm={() => revokeMut.mutate(record.id)}>
            <Button danger size="small" icon={<DeleteOutlined />}>
              吊销
            </Button>
          </Popconfirm>
        ),
    },
  ]

  return (
    <div>
      <Card
        title="API Keys"
        extra={
          <Space>
            <Input placeholder="Key 名称（可选）" value={name} onChange={(e) => setName(e.target.value)} style={{ width: 180 }} onPressEnter={() => createMut.mutate()} />
            <Button type="primary" icon={<PlusOutlined />} loading={createMut.isPending} onClick={() => createMut.mutate()}>
              创建 Key
            </Button>
          </Space>
        }
      >
        <Typography.Paragraph type="secondary">
          使用 API Key 调用 <Typography.Text code>POST /v1/audit</Typography.Text> 等接口（Authorization: Bearer &lt;key&gt;）。明文仅创建时显示一次。
        </Typography.Paragraph>
        <Table<APIKey> rowKey="id" loading={isLoading} dataSource={data?.keys ?? []} columns={columns} pagination={false} />
      </Card>

      <Modal
        title="Key 创建成功"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        footer={
          <Button
            type="primary"
            icon={<CopyOutlined />}
            onClick={() => {
              navigator.clipboard?.writeText(createdKey ?? '')
              message.success('已复制')
            }}
          >
            复制并关闭
          </Button>
        }
      >
        <Typography.Paragraph type="warning" style={{ marginBottom: 8 }}>
          请立即复制保存，明文不会再显示第二次：
        </Typography.Paragraph>
        <Typography.Paragraph>
          <Typography.Text code copyable style={{ fontSize: 13, wordBreak: 'break-all' }}>
            {createdKey}
          </Typography.Text>
        </Typography.Paragraph>
      </Modal>
    </div>
  )
}
