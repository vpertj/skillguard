package ioc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileSource(t *testing.T) {
	s := &FileSource{Path: "../../internal/bench/ioc/c2-ips.txt"}
	list, err := s.Fetch(context.Background())
	if err != nil {
		t.Fatalf("FileSource.Fetch 失败: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("FileSource 应加载到条目")
	}
}

func TestURLSource(t *testing.T) {
	fixture := "# comment\n91.92.242.30|clawhavoc|C2\nmalicious.example.com|payload|exfil\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Modified-Since") != "" {
			t.Errorf("首次请求不应带 If-Modified-Since")
		}
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.Write([]byte(fixture))
	}))
	defer srv.Close()

	s := &URLSource{URL: srv.URL, UserAgent: "test/1"}
	list, err := s.Fetch(context.Background())
	if err != nil {
		t.Fatalf("URLSource.Fetch 失败: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("拉取到 %d 条, want 2 (%+v)", len(list), list)
	}
	if list[0].Value != "91.92.242.30" || list[0].Category != "clawhavoc" {
		t.Errorf("解析错误: %+v", list[0])
	}
	if s.LastModified == "" {
		t.Error("应从响应头记录 Last-Modified")
	}
}

func TestURLSourceNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "booom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := &URLSource{URL: srv.URL}
	if _, err := s.Fetch(context.Background()); err == nil {
		t.Fatal("非 200 应返回错误")
	}
}

func TestLoadSourcesMerge(t *testing.T) {
	// 本地源 + HTTP 源合并，重复值去重。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("dup.example.com|a|\nunique.example.com|b|\n"))
	}))
	defer srv.Close()

	db, err := LoadSources(context.Background(),
		&URLSource{URL: srv.URL},
		&staticSource{entries: []IOC{{Value: "dup.example.com", Category: "a"}}},
	)
	if err != nil {
		t.Fatalf("LoadSources 失败: %v", err)
	}
	if db.Len() != 2 {
		t.Fatalf("Len = %d, want 2（去重后）", db.Len())
	}
}

func TestLoadSourcesPartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok.example.com|good|\n"))
	}))
	defer srv.Close()

	// 一个源失败，一个成功：返回 DB + 部分失败错误。
	db, err := LoadSources(context.Background(),
		&URLSource{URL: srv.URL},
		&URLSource{URL: "http://127.0.0.1:1/unreachable"}, // 必然失败
	)
	if err == nil {
		t.Fatal("存在失败源时应返回错误")
	}
	if db == nil || db.Len() == 0 {
		t.Fatalf("成功源应保留: db=%+v", db)
	}
}

// staticSource 测试用内嵌源。
type staticSource struct {
	entries []IOC
}

func (s *staticSource) Name() string { return "static" }
func (s *staticSource) Fetch(context.Context) ([]IOC, error) {
	return s.entries, nil
}

func TestProviderCacheAndRefresh(t *testing.T) {
	var fetches int32
	atomic.StoreInt32(&fetches, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Write([]byte("cache.example.com|pay|\n"))
	}))
	defer srv.Close()

	// TTL 较长：首次 Get 后，第二次 Get 应命中缓存不重新拉取。
	p := NewProvider([]Source{&URLSource{URL: srv.URL}}, 10*time.Hour)
	db, err := p.Get(context.Background())
	if err != nil || db.Len() == 0 {
		t.Fatalf("首次 Get 失败: db=%+v err=%v", db, err)
	}
	if atomic.LoadInt32(&fetches) != 1 {
		t.Fatalf("首次 Get 应拉取 1 次，实际 %d", atomic.LoadInt32(&fetches))
	}
	if _, err := p.Get(context.Background()); err != nil {
		t.Fatalf("二次 Get（热缓存）失败: %v", err)
	}
	if atomic.LoadInt32(&fetches) != 1 {
		t.Fatalf("TTL 内二次 Get 应命中缓存，实际拉取 %d 次", atomic.LoadInt32(&fetches))
	}
}

func TestProviderForceRefresh(t *testing.T) {
	var fetches int32
	atomic.StoreInt32(&fetches, 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Write([]byte("refresh.example.com|pay|\n"))
	}))
	defer srv.Close()

	p := NewProvider([]Source{&URLSource{URL: srv.URL}}, 10*time.Hour)
	if _, err := p.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("ForceRefresh 失败: %v", err)
	}
	if atomic.LoadInt32(&fetches) != 2 {
		t.Fatalf("ForceRefresh 应强制重拉，实际拉取 %d 次", atomic.LoadInt32(&fetches))
	}
	if p.Len() == 0 {
		t.Error("ForceRefresh 后缓存应非空")
	}
}

func TestProviderRefreshFailureKeepsOld(t *testing.T) {
	var reachable int32
	atomic.StoreInt32(&reachable, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&reachable) == 1 {
			w.Write([]byte("keep.example.com|pay|\n"))
		} else {
			http.Error(w, "down", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	p := NewProvider([]Source{&URLSource{URL: srv.URL}}, 10*time.Hour)
	if _, err := p.Get(context.Background()); err != nil {
		t.Fatal(err)
	}
	atomic.StoreInt32(&reachable, 0)
	// 强制刷新失败：应保留旧缓存（不返回 nil），并返回错误。
	db, err := p.ForceRefresh(context.Background())
	if err == nil {
		t.Fatal("刷新失败应返回错误")
	}
	if db == nil || db.Len() == 0 {
		t.Fatalf("刷新失败应保留旧缓存, db=%+v", db)
	}
}

// 确保 ParseIOC 能解析注释与空行。
func TestParseIOCComments(t *testing.T) {
	entries, err := ParseIOC(strings.NewReader("# comment\n\n1.2.3.4|c|\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Value != "1.2.3.4" {
		t.Fatalf("ParseIOC = %+v", entries)
	}
}
