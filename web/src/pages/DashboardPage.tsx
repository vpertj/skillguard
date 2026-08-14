import { useQuery } from '@tanstack/react-query'
import { Card, Col, Progress, Row, Statistic, Table, Tag, Typography } from 'antd'
import { SafetyCertificateOutlined, ThunderboltOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { auditApi, usageApi } from '../api/client'
import { useAuth } from '../stores/auth'
import type { AuditBrief } from '../api/types'

const levelColor: Record<string, string> = {
  safe: 'green',
  low: 'orange',
  high: 'red',
  malicious: 'volcano',
}

const levelText: Record<string, string> = {
  safe: '安全',
  low: '低风险',
  high: '高风险',
  malicious: '恶意',
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const user = useAuth((s) => s.user)
  const { data: usage } = useQuery({ queryKey: ['usage'], queryFn: usageApi.get })
  const { data: history } = useQuery({ queryKey: ['audits'], queryFn: auditApi.history })

  const usedPct = usage ? Math.min(100, Math.round((usage.used / Math.max(1, usage.quota)) * 100)) : 0

  const columns = [
    { title: 'ID', dataIndex: 'id', width: 60 },
    {
      title: '技能哈希',
      dataIndex: 'skill_hash',
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '评分',
      dataIndex: 'score',
      render: (v?: number) => (v === undefined || v === null ? '-' : <b>{v}</b>),
    },
    {
      title: '等级',
      dataIndex: 'level_key',
      render: (v: string) => <Tag color={levelColor[v] ?? 'default'}>{levelText[v] ?? v}</Tag>,
    },
    { title: '时间', dataIndex: 'created_at' },
  ]

  return (
    <div>
      <Typography.Title level={4}>仪表盘</Typography.Title>
      <Row gutter={16}>
        <Col span={8}>
          <Card>
            <Statistic title="账户" value={user?.email ?? '-'} prefix={<ThunderboltOutlined />} />
            <Typography.Text type="secondary">角色：{user?.role ?? '-'}</Typography.Text>
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic title="免费配额用量" value={usage ? `${usage.used} / ${usage.quota}` : '-'} suffix="次" />
            <Progress percent={usedPct} status={usedPct >= 100 ? 'exception' : 'active'} size="small" />
          </Card>
        </Col>
        <Col span={8}>
          <Card onClick={() => navigate('/audit')} style={{ cursor: 'pointer' }}>
            <Statistic title="快速操作" value="上传技能审计" prefix={<SafetyCertificateOutlined />} />
            <Typography.Text type="secondary">点击进入审计页</Typography.Text>
          </Card>
        </Col>
      </Row>

      <Card title="最近审计" style={{ marginTop: 16 }}>
        <Table<AuditBrief>
          rowKey="id"
          size="small"
          dataSource={history?.audits ?? []}
          columns={columns}
          pagination={{ pageSize: 5 }}
          locale={{ emptyText: '暂无审计记录，去上传第一个技能包吧' }}
        />
      </Card>
    </div>
  )
}
