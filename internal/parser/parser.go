// Package parser 解析技能包：采集文件、解析 SKILL.md frontmatter。
package parser

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Frontmatter SKILL.md YAML 头部字段。
type Frontmatter struct {
	Name         string   `yaml:"name" json:"name"`
	Description  string   `yaml:"description" json:"description"`
	AllowedTools []string `yaml:"allowed-tools" json:"allowed-tools"`
}

// MaxFileSize 可扫描文件大小上限（2MB，ARCHITECTURE §9.3）。
const MaxFileSize = 2 * 1024 * 1024

// binaryExts 二进制/非文本扩展名黑名单。
var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".bmp": true, ".webp": true, ".pdf": true, ".zip": true, ".gz": true,
	".tar": true, ".7z": true, ".rar": true, ".exe": true, ".dll": true,
	".so": true, ".dylib": true, ".bin": true, ".woff": true, ".woff2": true,
	".ttf": true, ".otf": true, ".mp3": true, ".mp4": true, ".avi": true,
	".mov": true, ".class": true, ".jar": true, ".pyc": true, ".docx": true,
	".xlsx": true, ".pptx": true, ".sqlite": true, ".db": true, ".wasm": true,
}

// CollectFiles 采集技能包文件。支持目录 / 单文件 / zip 压缩包。
// 返回的 files 为相对 root 的路径（斜杠分隔）；zip 输入解压到临时目录，
// 调用方审计结束后应 os.RemoveAll(root) 清理。
func CollectFiles(path string) (files []string, root string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", fmt.Errorf("访问路径失败: %w", err)
	}
	switch {
	case info.IsDir():
		return collectDir(path, path)
	case strings.EqualFold(filepath.Ext(path), ".zip"):
		root, err = os.MkdirTemp("", "skillguard-*")
		if err != nil {
			return nil, "", fmt.Errorf("创建临时目录失败: %w", err)
		}
		if err := extractZip(path, root); err != nil {
			os.RemoveAll(root)
			return nil, "", err
		}
		return collectDir(root, root)
	default:
		return []string{filepath.Base(path)}, filepath.Dir(path), nil
	}
}

func collectDir(dir, root string) ([]string, string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("遍历目录失败: %w", err)
	}
	return files, root, nil
}

func extractZip(zipPath, dest string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("打开 zip 失败: %w", err)
	}
	defer r.Close()
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// zip slip 防护：目标路径必须落在解压目录内，越界条目直接跳过
		target := filepath.Join(dest, filepath.Clean(filepath.FromSlash(f.Name)))
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// ParseSkillMD 解析 SKILL.md 内容：YAML frontmatter + 正文。
// 无 frontmatter 时容忍（fm 为零值，body 为全文）；frontmatter 损坏返回错误。
func ParseSkillMD(content string) (fm Frontmatter, body string, err error) {
	trimmed := strings.TrimPrefix(content, "\ufeff") // 去 BOM
	if !strings.HasPrefix(trimmed, "---\n") && trimmed != "---" {
		return fm, content, nil
	}
	rest := strings.TrimPrefix(trimmed, "---\n")
	end := strings.Index(rest, "\n---")
	if end == -1 {
		return fm, "", fmt.Errorf("frontmatter 未闭合（缺少结尾 ---）")
	}
	fmText := rest[:end]
	body = strings.TrimPrefix(rest[end:], "\n---")
	body = strings.TrimPrefix(body, "\n")
	if err := yaml.Unmarshal([]byte(fmText), &fm); err != nil {
		return Frontmatter{}, "", fmt.Errorf("frontmatter YAML 解析失败: %w", err)
	}
	return fm, body, nil
}

// IsScannable 判断文件是否可扫描：≤2MB、非二进制扩展名、前 512 字节无 NUL。
func IsScannable(path string, size int64) bool {
	if size > MaxFileSize {
		return false
	}
	if binaryExts[strings.ToLower(filepath.Ext(path))] {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return true // 打不开交给扫描阶段处理，不预先跳过
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := io.ReadFull(f, buf)
	return bytes.IndexByte(buf[:n], 0) == -1
}

// FindSkillMD 定位技能包中的 SKILL.md（大小写不敏感）。
func FindSkillMD(files []string) []string {
	var out []string
	for _, f := range files {
		if strings.EqualFold(filepath.Base(f), "skill.md") {
			out = append(out, f)
		}
	}
	return out
}
