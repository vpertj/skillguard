package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vpertj/skillguard/internal/parser"
)

// StaticSimulator 静态行为模拟后端：从技能包静态提取"潜在行为"清单。
// 它不真正执行代码（无特权、可测试、CI 可跑），而是作为沙箱的可验证占位——
// 描述"这个技能包理论上会做哪些文件/网络/进程/环境操作"，供审计报告参考。
// gVisor 后端就绪后替换它，得到真实的运行时行为。
type StaticSimulator struct{}

// Name 后端名。
func (s *StaticSimulator) Name() string { return "static" }

// Run 静态提取技能包的潜在行为。zip 输入由 parser 解压到临时目录，调用结束后清理。
func (s *StaticSimulator) Run(ctx context.Context, packagePath string, cfg Config) (*Report, error) {
	files, root, err := parser.CollectFiles(packagePath)
	if err != nil {
		return nil, err
	}
	// 仅 zip 输入会解压到独立临时目录，需要清理；目录/单文件 root 指向用户路径，绝不删除。
	if strings.EqualFold(filepath.Ext(packagePath), ".zip") {
		defer os.RemoveAll(root)
	}

	report := &Report{Backend: s.Name()}
	seen := map[string]bool{}
	add := func(dst *[]string, v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		*dst = append(*dst, v)
	}

	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := filepath.Join(root, filepath.FromSlash(f))
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if !parser.IsScannable(path, info.Size()) {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(content)
		lower := strings.ToLower(f)

		for _, m := range captureMatches(fileReadRe, text) {
			add(&report.FileReads, m)
		}
		for _, m := range captureMatches(fileWriteRe, text) {
			add(&report.FileWrites, m)
		}
		for _, m := range captureMatches(processRe, text) {
			add(&report.ProcessTree, m)
		}
		for _, m := range captureMatches(envReadRe, text) {
			add(&report.EnvReads, m)
		}
		for _, m := range captureMatches(networkRe, text) {
			add(&report.NetworkConnections, m)
		}
		if isExecutableExt(lower) {
			report.PVBehavior = "技能包含可执行脚本，已静态提取潜在行为（未真正执行）"
		}
	}

	// 输出稳定排序，保证报告确定性。
	sort.Strings(report.FileReads)
	sort.Strings(report.FileWrites)
	sort.Strings(report.ProcessTree)
	sort.Strings(report.EnvReads)
	sort.Strings(report.NetworkConnections)
	return report, nil
}

// captureMatches 用正则提取匹配串：遍历所有捕获组，取第一个非空的（更具体的目标）；
// 全部为空时回退取完整匹配。防止不同分支捕获组位置不一致导致的越界或空值。
func captureMatches(re *regexp.Regexp, text string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			matched := ""
			for _, g := range m[1:] {
				if g != "" {
					matched = g
					break
				}
			}
			if matched != "" {
				out = append(out, matched)
				continue
			}
		}
		if len(m) > 0 {
			out = append(out, m[0])
		}
	}
	return out
}

// 行为提取模式（中性描述，不判恶意；仅用于"记录会做什么"）。
var (
	// 文件读取（首参为路径表达式）
	fileReadRe = regexp.MustCompile(`(?i)\b(?:open|read|read_text|readlines)\s*\(\s*["']([^"']+)["']`)
	// 文件写入：open(...,"w") 等（捕获路径参数）
	fileWriteRe = regexp.MustCompile(`(?i)\bopen\s*\(\s*["']([^"']+)["']\s*,\s*["']w["']`)
	// 进程/命令调用：subprocess/os.system/exec/bash -c，以及 curl|bash 管道执行（captureMatches 无捕获组时取完整匹配）
	processRe = regexp.MustCompile(`(?i)(?:\bsubprocess\.\w+\s*\(|os\.system\s*\(|\bexec(?:ve|l)?\s*\(|\b(?:bash|sh|zsh)\s+-c\b|\|\s*(?:ba)?sh\b)`)
	// 环境变量读取（捕获变量名）
	envReadRe = regexp.MustCompile(`(?i)\b(?:os\.environ(?:\.get)?|os\.getenv|process\.env|getenv)\s*\(\s*["']([^"']+)["']`)
	// 网络外联：仅匹配"实际发起网络调用"的命令/方法（curl/wget/requests/fetch 等），
	// 并捕获其目标（URL 优先；无 URL 时取完整匹配），避免把文档里的裸 URL 引用误判为外联。
	networkRe = regexp.MustCompile(`(?i)\b(?:curl|wget)\s+(?:-s\s+|--silent\s+)?(?:[a-z-]+\s+)*["']?((?:https?://)[\w.-]+(?::\d+)?(?:/[\w./?=&-]*)?)["']?|\b(?:requests|urllib\.(?:request|parse))\.(?:get|post|urlopen)\s*\(\s*["']((?:https?://)[^"']+)["']`)
)

// isExecutableExt 判断是否为常见可执行/脚本扩展名。
func isExecutableExt(lower string) bool {
	for _, ext := range []string{".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".pl", ".rb"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
