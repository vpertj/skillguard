import { Card, Col, Progress, Row, Space, Tag, Typography } from 'antd'
import type { ScoreResult } from '../api/types'

const levelColor: Record<string, string> = {
  safe: 'green',
  low: 'orange',
  high: 'red',
  malicious: 'volcano',
}

// 评分展示卡：环形进度 + 等级 + 行为链加成 + 维度分解
export default function ScoreCard({ score }: { score: ScoreResult }) {
  return (
    <Card title="风险评分" style={{ height: '100%' }}>
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          <Progress
            type="dashboard"
            percent={score.score}
            format={(p) => (
              <span>
                <span style={{ fontSize: 24, fontWeight: 700 }}>{p}</span>
                <span style={{ fontSize: 12, color: '#999' }}> / 100</span>
              </span>
            )}
            strokeColor={score.level_key === 'safe' ? '#52c41a' : score.level_key === 'low' ? '#faad14' : score.level_key === 'high' ? '#ff4d4f' : '#cf1322'}
          />
          <div>
            <Typography.Title level={4} style={{ margin: 0 }}>
              {score.icon} {score.level}
            </Typography.Title>
            <Tag color={levelColor[score.level_key] ?? 'default'} style={{ marginTop: 8 }}>
              {score.level_key}
            </Tag>
            {score.bonus > 0 && <Typography.Paragraph type="secondary" style={{ marginTop: 8, fontSize: 12 }}>行为链加成 +{score.bonus}</Typography.Paragraph>}
          </div>
        </div>

        {score.notes.length > 0 && (
          <div>
            {score.notes.map((n) => (
              <Typography.Paragraph key={n} type="warning" style={{ margin: 0, fontSize: 13 }}>
                · {n}
              </Typography.Paragraph>
            ))}
          </div>
        )}

        <Row gutter={[12, 12]}>
          {score.breakdown.map((b) => (
            <Col span={24} key={b.dimension}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13 }}>
                <span>{b.dimension}</span>
                <span>
                  <b>{b.contrib}</b> 分（最高命中权重 {b.group_max_weight} × {b.weight}）
                </span>
              </div>
              <Progress percent={Math.min(100, (b.contrib / 40) * 100)} size="small" showInfo={false} strokeColor="#2f54eb" />
            </Col>
          ))}
        </Row>
      </Space>
    </Card>
  )
}
