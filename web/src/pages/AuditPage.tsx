import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { App as AntApp, Alert, Card, Radio, Space, Typography, Upload } from 'antd'
import { InboxOutlined, RobotOutlined } from '@ant-design/icons'
import { auditApi } from '../api/client'
import type { AuditResp } from '../api/types'
import ReportView from '../components/ReportView'

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

      {result && (
        <div style={{ marginTop: 16 }}>
          <ReportView report={result.report} llmResults={result.llm_results} cached={result.cached} />
        </div>
      )}
    </div>
  )
}
