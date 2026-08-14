import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { App as AntApp, Alert, Card, Col, Collapse, Descriptions, Row, Tag, Typography, Upload } from 'antd'
import { InboxOutlined } from '@ant-design/icons'
import { auditApi } from '../api/client'
import type { AuditResp, Report } from '../api/types'
import ScoreCard from '../components/ScoreCard'
import FindingsTable from '../components/FindingsTable'

const levelColor: Record<string, string> = {
  safe: 'green',
  low: 'orange',
  high: 'red',
  malicious: 'volcano',
}

export default function AuditPage() {
  const { message } = AntApp.useApp()
  const queryClient = useQueryClient()
  const [result, setResult] = useState<AuditResp | null>(null)
  const [error, setError] = useState<string | null>(null)

  const auditMut = useMutation({
    mutationFn: (file: File) => auditApi.upload(file),
    onSuccess: (resp) => {
      setResult(resp)
      setError(null)
      queryClient.invalidateQueries({ queryKey: ['audits'] })
      queryClient.invalidateQueries({ queryKey: ['usage'] })
      if (resp.cached) message.info('同一技能包今日已审计过，返回缓存结果（不计费）')
    },
    onError: (e) => {
      setError(e instanceof Error ? e.message : '审计失败')
      setResult(null)
    },
  })

  const report: Report | null = result?.report ?? null

  return (
    <div>
      <Typography.Title level={4}>技能审计</Typography.Title>
      <Card>
        <Upload.Dragger
          accept=".zip"
          maxCount={1}
          showUploadList={false}
          disabled={auditMut.isPending}
          beforeUpload={(file) => {
            if (!file.name.toLowerCase().endsWith('.zip')) {
              message.error('仅支持 zip 压缩包')
              return Upload.LIST_IGNORE
            }
            auditMut.mutate(file)
            return false
          }}
        >
          <p className="ant-upload-drag-icon">
            <InboxOutlined />
          </p>
          <p className="ant-upload-text">点击或拖拽技能包 zip 到此处上传审计</p>
          <p className="ant-upload-hint">支持 SKILL.md + 附属脚本的压缩包，审计后返回 0-100 风险评分与命中明细</p>
        </Upload.Dragger>
        {auditMut.isPending && <Alert style={{ marginTop: 16 }} type="info" showIcon message="正在审计技能包，请稍候…" />}
        {error && <Alert style={{ marginTop: 16 }} type="error" showIcon message={error} />}
      </Card>

      {report && (
        <>
          {result?.cached && (
            <Alert style={{ marginTop: 16 }} type="info" showIcon message="本次为缓存结果（同日同内容重复审计不计费）" />
          )}
          <Row gutter={16} style={{ marginTop: 16 }}>
            <Col span={10}>
              <ScoreCard score={report.score} />
            </Col>
            <Col span={14}>
              <Card title="技能信息" style={{ height: '100%' }}>
                <Descriptions column={1} size="small">
                  <Descriptions.Item label="名称">{report.skill_md?.frontmatter.name ?? '-'}</Descriptions.Item>
                  <Descriptions.Item label="描述">{report.skill_md?.frontmatter.description ?? '-'}</Descriptions.Item>
                  <Descriptions.Item label="扫描文件">{report.scanned_files}（跳过 {report.skipped_files}）</Descriptions.Item>
                  <Descriptions.Item label="规则库版本">{report.rules_version}</Descriptions.Item>
                  <Descriptions.Item label="命中类别">
                    {report.score.hit_categories.length > 0
                      ? report.score.hit_categories.map((c) => <Tag key={c} color={levelColor[report.score.level_key]}>{c}</Tag>)
                      : '-'}
                  </Descriptions.Item>
                </Descriptions>
              </Card>
            </Col>
          </Row>

          <Card title={`命中明细（${report.findings.length}）`} style={{ marginTop: 16 }}>
            <FindingsTable findings={report.findings} />
          </Card>

          {report.llm_review_rules.length > 0 && (
            <Card title="待 LLM 复核规则" style={{ marginTop: 16 }}>
              <Collapse
                items={report.llm_review_rules.map((r) => ({
                  key: r.id,
                  label: `${r.id} ${r.name}`,
                  children: (
                    <Typography.Paragraph style={{ margin: 0 }}>
                      {r.rationale}
                      <br />
                      <Typography.Text type="secondary">误报提示：{r.false_positive_note}</Typography.Text>
                    </Typography.Paragraph>
                  ),
                }))}
              />
            </Card>
          )}
        </>
      )}
    </div>
  )
}
