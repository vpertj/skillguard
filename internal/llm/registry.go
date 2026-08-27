package llm

import (
	"context"
	"errors"
	"sync"
)

// Registry 管理当前 LLM Provider，支持运行时热更新 API Key（无需重启服务）。
// 并发安全：读请求持当前 provider，更新时替换。
type Registry struct {
	mu      sync.RWMutex
	current Provider
	baseURL string
	model   string
	enabled bool
}

// NewRegistry 创建空注册表（未启用，深度分析返回未配置错误）。
func NewRegistry() *Registry {
	return &Registry{}
}

// Enable 用环境变量 key 启用（启动时调用）。
func (r *Registry) Enable(apiKey, baseURL, model string) {
	if baseURL == "" {
		baseURL = "https://api.deepseek.com"
	}
	if model == "" {
		model = "deepseek-v4-flash"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = NewDeepSeekWithBase(apiKey, baseURL, model)
	r.baseURL = baseURL
	r.model = model
	r.enabled = true
}

// UpdateKey 热更新 API Key（管理员后台操作后立即生效）。
func (r *Registry) UpdateKey(apiKey string) error {
	if apiKey == "" {
		return errors.New("API Key 不能为空")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = NewDeepSeekWithBase(apiKey, r.baseURLOrDefault(), r.modelOrDefault())
	r.enabled = true
	return nil
}

// Disable 停用（管理员清空 key 时）。
func (r *Registry) Disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = nil
	r.enabled = false
}

// Enabled 是否已配置可用。
func (r *Registry) Enabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

// ReviewFindings 转发二次裁决到当前 provider；未配置或 provider 不支持时返回空结果（不报错）。
func (r *Registry) ReviewFindings(ctx context.Context, req ReviewRequest) (*ReviewResult, error) {
	r.mu.RLock()
	p := r.current
	r.mu.RUnlock()
	rp, ok := p.(ReviewProvider)
	if !ok {
		return &ReviewResult{}, nil
	}
	return rp.ReviewFindings(ctx, req)
}

// Model 当前模型名（未启用返回默认名）。
func (r *Registry) Model() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.modelOrDefault()
}

func (r *Registry) baseURLOrDefault() string {
	if r.baseURL != "" {
		return r.baseURL
	}
	return "https://api.deepseek.com"
}

func (r *Registry) modelOrDefault() string {
	if r.model != "" {
		return r.model
	}
	return "deepseek-v4-flash"
}

// Analyze 委托当前 provider；未启用返回错误（调用方转 503）。
func (r *Registry) Analyze(ctx context.Context, req AnalyzeRequest) (*AnalyzeResult, error) {
	r.mu.RLock()
	p := r.current
	enabled := r.enabled
	r.mu.RUnlock()
	if !enabled || p == nil {
		return nil, ErrNotConfigured
	}
	return p.Analyze(ctx, req)
}

// ErrNotConfigured LLM 未配置。
var ErrNotConfigured = errors.New("LLM 深度分析未配置")
