import { Card, Col, Progress, Row, Space, Tag, Typography } from 'antd'
import type { ScoreResult } from '../api/types'

const levelColor: Record<string, string> = {
  safe: 'green',
  low: 'orange',
  high: 'red',
  malicious: 'volcano',
}

// 分级刻度条：0-100 四段（安全/低风险/高风险/恶意），指针标出当前分数位置
function RiskScale({ score }: { score: number }) {
  const segs = [
    { from: 0, to: 20, color: '#52c41a', label: '安全' },
    { from: 20, to: 50, color: '#faad14', label: '低风险' },
    { from: 50, to: 80, color: '#ff4d4f', label: '高风险' },
    { from: 80, to: 100, color: '#cf1322', label: '恶意' },
  ]
  const pct = Math.min(100, Math.max(0, score))
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ position: 'relative', height: 10, borderRadius: 5, overflow: 'hidden', display: 'flex' }}>
        {segs.map((s) => (
          <div key={s.from} style={{ width: `${s.to - s.from}%`, background: s.color }} title={`${s.from}-${s.to} ${s.label}`} />
        ))}
        <div
          style={{
            position: 'absolute',
            left: `${pct}%`,
            top: -4,
            width: 3,
            height: 18,
            background: '#fff',
            border: '1px solid rgba(0,0,0,0.4)',
            borderRadius: 2,
            transform: 'translateX(-1px)',
            boxShadow: '0 1px 3px rgba(0,0,0,0.3)',
          }}
        />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#999', marginTop: 4 }}>
        <span>0 安全</span>
        <span>100 恶意</span>
      </div>
    </div>
  )
}

// 评分展示卡：环形进度 + 等级 + 行为链加成 + 维度分解
export default function ScoreCard({ score }: { score: ScoreResult }) {
  return (
    <Card title="风险评分" style={{ height: '100%' }}>
      <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
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

        <Typography.Text type="secondary" style={{ fontSize: 12, display: 'block' }}>
          分数越高风险越高：0 分完全安全，100 分最高风险
        </Typography.Text>
        <RiskScale score={score.score} />

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
