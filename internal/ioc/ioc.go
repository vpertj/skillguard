package ioc

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// IOC 是威胁情报条目（C2 IP / 恶意域名 / 恶意发布者）。
type IOC struct {
	Value    string // 原始值（IP/域名/发布者）
	Category string // clawhavoc / payload / exfil ...
	Notes    string
}

// DB 加载后的 IOC 数据库（值 → 条目）。
type DB struct {
	ips     map[string]IOC
	domains map[string]IOC
}

// Load 从格式为 `value|category|notes` 的文件加载 IOC（# 开头为注释）。
// 文件缺失时跳过（开源版无 IOC 时降级，不报错）。
func Load(paths ...string) (*DB, error) {
	var entries []IOC
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue // 文件缺失跳过（开源版无 IOC 时降级）
		}
		list, err := ParseIOC(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("解析 IOC 文件 %s: %w", path, err)
		}
		entries = append(entries, list...)
	}
	return BuildDB(entries), nil
}

// ParseIOC 从 reader 解析 `value|category|notes` 行格式（# 开头为注释，空行跳过）。
func ParseIOC(r io.Reader) ([]IOC, error) {
	var entries []IOC
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		entry := IOC{Value: strings.TrimSpace(parts[0])}
		if len(parts) > 1 {
			entry.Category = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			entry.Notes = strings.TrimSpace(parts[2])
		}
		if entry.Value == "" {
			continue
		}
		entries = append(entries, entry)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// BuildDB 从 IOC 条目构建 DB（按 IP/域名分桶，重复值去重）。
func BuildDB(entries []IOC) *DB {
	db := &DB{ips: map[string]IOC{}, domains: map[string]IOC{}}
	for _, e := range entries {
		if e.Value == "" {
			continue
		}
		if isIP(e.Value) {
			if _, exists := db.ips[e.Value]; !exists {
				db.ips[e.Value] = e
			}
		} else {
			if _, exists := db.domains[e.Value]; !exists {
				db.domains[e.Value] = e
			}
		}
	}
	return db
}

// IP 正则（IPv4）。
var ipRe = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

func isIP(s string) bool { return ipRe.MatchString(s) }

// Len 返回加载的 IOC 总数。
func (db *DB) Len() int { return len(db.ips) + len(db.domains) }

// Match 在内容中查找已知 IOC（IP 精确匹配，域名子串匹配）。
// 返回 (条目, 命中的原始文本片段, 是否命中)。
func (db *DB) Match(content string) (IOC, string, bool) {
	for ip, e := range db.ips {
		if strings.Contains(content, ip) {
			return e, ip, true
		}
	}
	for domain, e := range db.domains {
		if strings.Contains(content, domain) {
			return e, domain, true
		}
	}
	return IOC{}, "", false
}

// MatchAll 返回内容中命中的全部 IOC（去重）。
func (db *DB) MatchAll(content string) []IOC {
	var out []IOC
	seen := map[string]bool{}
	for ip, e := range db.ips {
		if strings.Contains(content, ip) && !seen[ip] {
			out = append(out, e)
			seen[ip] = true
		}
	}
	for domain, e := range db.domains {
		if strings.Contains(content, domain) && !seen[domain] {
			out = append(out, e)
			seen[domain] = true
		}
	}
	return out
}
