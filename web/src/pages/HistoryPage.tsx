import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Modal, Table, Tag, Typography } from 'antd'
import { EyeOutlined } from '@ant-design/icons'
import { auditApi } from '../api/client'
import type { AuditBrief, Report } from '../api/types'
import ReportView from '../components/ReportView'

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
  const [viewing, setViewing] = useState<AuditBrief | null>(null)
  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ['audit-detail', viewing?.id],
    queryFn: () => auditApi.detail(viewing!.id),
    enabled: !!viewing,
  })

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
    {
      title: '操作',
      width: 110,
      render: (_: unknown, record: AuditBrief) => (
        <Button size="small" icon={<EyeOutlined />} onClick={() => setViewing(record)}>
          查看报告
        </Button>
      ),
    },
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

      <Modal
        open={!!viewing}
        onCancel={() => setViewing(null)}
        footer={null}
        width={1000}
        title={
          viewing ? (
            <span>
              审计报告 #{viewing.id} ——{' '}
              <Tag color={levelColor[viewing.level_key] ?? 'default'}>{levelText[viewing.level_key] ?? viewing.level_key}</Tag>
              {viewing.score !== undefined && viewing.score !== null ? <b> {viewing.score} 分</b> : null}
            </span>
          ) : null
        }
      >
        {detailLoading ? (
          <Typography.Paragraph type="secondary">加载报告中…</Typography.Paragraph>
        ) : detail ? (
          <ReportView report={detail.report as Report} llmResults={detail.llm_results} />
        ) : (
          <Typography.Paragraph type="danger">报告加载失败</Typography.Paragraph>
        )}
      </Modal>
    </div>
  )
}
