package ioc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Source 是 IOC 数据源抽象：本地文件与 HTTP feed 都实现此接口。
// 新增数据源（数据库、供应商 API）只需实现此接口，无需改动 DB 构建逻辑。
type Source interface {
	// Name 数据源名（用于日志/排障）。
	Name() string
	// Fetch 拉取并解析 IOC 条目。格式约定同 ParseIOC：`value|category|notes` 行。
	Fetch(ctx context.Context) ([]IOC, error)
}

// FileSource 从本地文件加载 IOC（现有 `internal/bench/ioc/*.txt` 的包装）。
type FileSource struct {
	Path string
}

func (s *FileSource) Name() string { return "file:" + s.Path }

func (s *FileSource) Fetch(_ context.Context) ([]IOC, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseIOC(f)
}

// URLSource 从 HTTP(S) URL 拉取 IOC feed（自动刷新、可持续更新的威胁情报源）。
type URLSource struct {
	URL        string
	HTTPClient *http.Client
	// UserAgent 可选，标注客户端身份（礼貌拉取）。
	UserAgent string
	// LastModified 记录最近一次成功拉取的响应头（可选，用于条件请求）。
	LastModified string
}

func (s *URLSource) Name() string { return "url:" + s.URL }

func (s *URLSource) client() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Fetch 从 URL 拉取 IOC。非 200 状态返回错误；解析失败返回错误（不静默吞掉，
// 保证 feed 质量——上游异常时宁可降级也不加载损坏数据）。
func (s *URLSource) Fetch(ctx context.Context) ([]IOC, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造 IOC feed 请求失败: %w", err)
	}
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	if s.LastModified != "" {
		req.Header.Set("If-Modified-Since", s.LastModified)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("拉取 IOC feed %s 失败: %w", s.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IOC feed %s 返回 %d", s.URL, resp.StatusCode)
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		s.LastModified = lm
	}
	// 限制响应体大小，防止恶意/异常 feed 撑爆内存。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8 MiB
	if err != nil {
		return nil, fmt.Errorf("读取 IOC feed 失败: %w", err)
	}
	return ParseIOC(strings.NewReader(string(body)))
}

// LoadSources 从多个数据源合并构建 DB（去重）。某个源失败时跳过并继续，
// 失败的源名随错误返回，供调用方决定降级策略（不会因单源故障整体失败）。
func LoadSources(ctx context.Context, sources ...Source) (*DB, error) {
	var entries []IOC
	var failed []string
	for _, s := range sources {
		list, err := s.Fetch(ctx)
		if err != nil {
			failed = append(failed, s.Name()+"("+err.Error()+")")
			continue
		}
		entries = append(entries, list...)
	}
	db := BuildDB(entries)
	if len(failed) > 0 {
		// 部分源失败：返回 DB + 失败摘要（DB 可能仍可用，调用方权衡）。
		return db, fmt.Errorf("部分 IOC 源加载失败: %s", strings.Join(failed, "; "))
	}
	return db, nil
}

// Provider 并发安全的 IOC 缓存提供者：按 TTL 刷新，避免每次审计重读磁盘/重复拉取.
// 调用方通过 Get() 拿到最近的 DB（TTL 内返回缓存，过期后后台刷新）。
type Provider struct {
	mu       sync.Mutex
	sources  []Source
	ttl      time.Duration
	cache    *DB
	lastSync time.Time
}

// NewProvider 构造带 TTL 刷新的 IOC 提供者（ttl 为 0 时默认 5 分钟）。
func NewProvider(sources []Source, ttl time.Duration) *Provider {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Provider{sources: sources, ttl: ttl}
}

// Get 返回最近的 IOC DB。若缓存过期或为首次加载，则同步刷新。
// 刷新失败时降级返回旧缓存（若存在），并同时返回错误供调用方记录。
func (p *Provider) Get(ctx context.Context) (*DB, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache != nil && time.Since(p.lastSync) < p.ttl {
		return p.cache, nil
	}
	db, err := LoadSources(ctx, p.sources...)
	if err != nil {
		// 刷新失败：保留旧缓存（可能已过期但仍可用），返回错误。
		if p.cache != nil {
			return p.cache, err
		}
		return nil, err
	}
	p.cache = db
	p.lastSync = time.Now()
	return db, nil
}

// ForceRefresh 强制刷新并更新缓存（供定时任务/管理后台调用）。
func (p *Provider) ForceRefresh(ctx context.Context) (*DB, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	db, err := LoadSources(ctx, p.sources...)
	if err != nil {
		return p.cache, err
	}
	p.cache = db
	p.lastSync = time.Now()
	return db, nil
}

// Len 返回当前缓存大小（未加载时为 0）。
func (p *Provider) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache == nil {
		return 0
	}
	return p.cache.Len()
}
