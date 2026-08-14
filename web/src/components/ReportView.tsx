import { Card, Col, Collapse, Descriptions, Row, Space, Tag, Typography } from 'antd'
import type { LLMResult, Report } from '../api/types'
import ScoreCard from './ScoreCard'
import FindingsTable from './FindingsTable'

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

// 完整报告视图：评分卡 + 技能信息 + 命中明细 + LLM 语义分析 + 待复核规则
// 审计页（新结果）与历史详情（存档报告）共用
export default function ReportView({ report, llmResults, cached }: { report: Report; llmResults?: LLMResult[]; cached?: boolean }) {
  return (
    <div>
      {cached && (
        <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 8, fontSize: 12 }}>
          该结果为历史存档报告（同日同内容重复审计不计费）
        </Typography.Text>
      )}
      <Row gutter={16}>
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

      {llmResults && llmResults.length > 0 && (
        <Card title="LLM 语义分析（深度分析）" style={{ marginTop: 16 }}>
          {llmResults.map((r: LLMResult) => (
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
    </div>
  )
}
