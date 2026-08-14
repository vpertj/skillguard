import { useMutation, useQuery } from '@tanstack/react-query'
import { App as AntApp, Alert, Button, Card, Descriptions, Form, Input, Popconfirm, Space, Tag, Typography } from 'antd'
import { KeyOutlined, SaveOutlined, StopOutlined } from '@ant-design/icons'
import { adminApi } from '../api/client'

export default function AdminSettingsPage() {
  const { message } = AntApp.useApp()
  const [form] = Form.useForm<{ api_key: string }>()

  const { data, refetch, isLoading } = useQuery({ queryKey: ['admin-deepseek'], queryFn: adminApi.getDeepSeek })

  const saveMut = useMutation({
    mutationFn: (api_key: string) => adminApi.putDeepSeek(api_key),
    onSuccess: (d) => {
      message.success(d.configured ? 'DeepSeek Key 已保存并立即生效' : '深度分析已停用')
      form.resetFields()
      refetch()
    },
    onError: (e) => message.error(e instanceof Error ? e.message : '保存失败'),
  })

  return (
    <div>
      <Typography.Title level={4}>系统设置</Typography.Title>
      <Card title="DeepSeek 深度分析配置" loading={isLoading}>
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="状态">
              {data?.configured ? <Tag color="green">已配置</Tag> : <Tag color="orange">未配置</Tag>}
            </Descriptions.Item>
            {data?.configured && (
              <>
                <Descriptions.Item label="模型">{data.model}</Descriptions.Item>
                <Descriptions.Item label="接口地址">{data.base_url}</Descriptions.Item>
              </>
            )}
          </Descriptions>

          {!data?.configured && (
            <Alert type="info" showIcon title="深度分析暂未启用" description="配置 DeepSeek API Key 后，用户可在审计页使用「深度分析」模式（角色伪装 / 声明-行为不一致的语义检测）。" />
          )}

          <Form form={form} layout="vertical" onFinish={(v: { api_key: string }) => saveMut.mutate(v.api_key.trim())}>
            <Form.Item
              name="api_key"
              label={data?.configured ? '更新 DeepSeek API Key' : 'DeepSeek API Key'}
              rules={[{ required: true, message: '请输入 API Key' }, { pattern: /^sk-/, message: 'Key 应以 sk- 开头' }]}
              extra="加密存储（AES-GCM），保存后立即生效，无需重启服务"
            >
              <Input.Password prefix={<KeyOutlined />} placeholder="sk-..." autoComplete="off" />
            </Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saveMut.isPending}>
                {data?.configured ? '更新 Key' : '保存并启用'}
              </Button>
              {data?.configured && (
                <Popconfirm title="删除后深度分析立即停用，确认删除配置？" onConfirm={() => saveMut.mutate('')}>
                  <Button danger icon={<StopOutlined />}>
                    删除配置
                  </Button>
                </Popconfirm>
              )}
            </Space>
          </Form>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            Key 由平台方统一管理，普通用户不可见。更换 Key 会立即生效。
          </Typography.Text>
        </Space>
      </Card>
    </div>
  )
}
