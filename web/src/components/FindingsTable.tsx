import { Table, Tag, Typography } from 'antd'
import type { Finding } from '../api/types'

const severityColor: Record<string, string> = {
  critical: 'volcano',
  high: 'red',
  medium: 'orange',
  low: 'blue',
}

const severityText: Record<string, string> = {
  critical: '严重',
  high: '高',
  medium: '中',
  low: '低',
}

// 命中明细表格
export default function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <Typography.Paragraph type="secondary" style={{ padding: '16px 0' }}>
        未命中任何规则，技能包看起来是安全的。
      </Typography.Paragraph>
    )
  }
  const columns = [
    {
      title: '规则',
      dataIndex: 'rule_id',
      width: 90,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    { title: '名称', dataIndex: 'rule_name' },
    {
      title: '类别',
      dataIndex: 'category',
      width: 150,
      render: (v: string) => <Tag>{v}</Tag>,
    },
    {
      title: '严重度',
      dataIndex: 'severity',
      width: 80,
      render: (v: string) => <Tag color={severityColor[v] ?? 'default'}>{severityText[v] ?? v}</Tag>,
    },
    { title: '文件', dataIndex: 'file', width: 180 },
    { title: '行', dataIndex: 'line', width: 60 },
    {
      title: '命中片段',
      dataIndex: 'snippet',
      render: (v: string) => <Typography.Text code style={{ fontSize: 12 }}>{v}</Typography.Text>,
    },
  ]
  return (
    <Table<Finding>
      rowKey={(r) => `${r.rule_id}-${r.file}-${r.line}`}
      size="small"
      dataSource={findings}
      columns={columns}
      pagination={false}
      scroll={{ x: 900 }}
    />
  )
}
