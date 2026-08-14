import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { App as AntApp, Alert, Card, Col, Collapse, Descriptions, Radio, Row, Space, Tag, Typography, Upload } from 'antd'
import { InboxOutlined, RobotOutlined } from '@ant-design/icons'
import { auditApi } from '../api/client'
import type { AuditResp, LLMResult, Report } from '../api/types'
import ScoreCard from '../components/ScoreCard'
import FindingsTable from '../components/FindingsTable'

const levelColor: Record<string, string> = {
  safe: 'green',
  low: 'orange',
  high: 'red',
  malicious: 'volcano',
}

const verdictTag: Record<string, { color: string; text: string }> = {
  suspicious: { color: 'volcano', text: '可疑' },
  clean: { color: 'green', text: '正常' },
  unknown: { color: 'default', text: '无法判定' },
}

export default function AuditPage() {
  const { message } = AntApp.useApp()
  const queryClient = useQueryClient()
  const [result, setResult] = useState<AuditResp | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [deepMode, setDeepMode] = useState(false)

  const auditMut = useMutation({
    mutationFn: (file: File) => (deepMode ? auditApi.deep(file) : auditApi.upload(file)),
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
        <Space style={{ marginBottom: 16 }}>
          <Radio.Group value={deepMode} onChange={(e) => setDeepMode(e.target.value)} optionType="button" buttonStyle="solid">
            <Radio.Button value={false}>标准审计（免费）</Radio.Button>
            <Radio.Button value={true}>
              <RobotOutlined /> 深度分析（LLM 语义检测）
            </Radio.Button>
          </Radio.Group>
          {deepMode && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              额外检测角色伪装 / 声明-行为不一致，消耗深度分析配额
            </Typography.Text>
          )}
        </Space>
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
        {auditMut.isPending && <Alert style={{ marginTop: 16 }} type="info" showIcon title="正在审计技能包，请稍候…" />}
        {error && <Alert style={{ marginTop: 16 }} type="error" showIcon title={error} />}
      </Card>

      {report && (
        <>
          {result?.cached && (
            <Alert style={{ marginTop: 16 }} type="info" showIcon title="本次为缓存结果（同日同内容重复审计不计费）" />
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

          {result?.llm_results && result.llm_results.length > 0 && (
            <Card title="LLM 语义分析（深度分析）" style={{ marginTop: 16 }}>
              {result.llm_results.map((r: LLMResult) => (
                <div key={r.rule_id} style={{ padding: '8px 0', borderBottom: '1px solid #f0f0f0' }}>
                  <Space>
                    <Typography.Text strong>{r.rule_id}</Typography.Text>
                    <Typography.Text>{r.rule_id === 'RS-018' ? '角色伪装' : '声明-行为不一致'}</Typography.Text>
                    <Tag color={verdictTag[r.verdict]?.color}>{verdictTag[r.verdict]?.text ?? r.verdict}</Tag>
                    {r.confidence && <Typography.Text type="secondary" style={{ fontSize: 12 }}>置信度：{r.confidence}</Typography.Text>}
                  </Space>
                  <Typography.Paragraph style={{ margin: '4px 0 0', fontSize: 13 }}>
                    {r.reason || '（无说明）'}
                  </Typography.Paragraph>
                </div>
              ))}
            </Card>
          )}

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
