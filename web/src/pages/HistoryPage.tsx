import { useQuery } from '@tanstack/react-query'
import { Card, Table, Tag, Typography } from 'antd'
import { auditApi } from '../api/client'
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

export default function HistoryPage() {
  const { data, isLoading } = useQuery({ queryKey: ['audits'], queryFn: auditApi.history })

  const columns = [
    { title: 'ID', dataIndex: 'id', width: 70 },
    {
      title: '技能哈希',
      dataIndex: 'skill_hash',
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '评分',
      dataIndex: 'score',
      sorter: (a: AuditBrief, b: AuditBrief) => (a.score ?? 0) - (b.score ?? 0),
      render: (v?: number) => (v === undefined || v === null ? '-' : <b>{v}</b>),
    },
    {
      title: '等级',
      dataIndex: 'level_key',
      render: (v: string) => <Tag color={levelColor[v] ?? 'default'}>{levelText[v] ?? v}</Tag>,
    },
    { title: '审计时间', dataIndex: 'created_at' },
  ]

  return (
    <div>
      <Typography.Title level={4}>审计历史</Typography.Title>
      <Card>
        <Table<AuditBrief>
          rowKey="id"
          loading={isLoading}
          dataSource={data?.audits ?? []}
          columns={columns}
          pagination={{ pageSize: 20 }}
          locale={{ emptyText: '暂无审计记录' }}
        />
      </Card>
    </div>
  )
}
