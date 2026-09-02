// Command audit 提供 SkillGuard CLI：本地审计技能包（目录/单文件/zip）。
// 与 Web API 共用同一引擎内核，是私有化/企业自托管形态。
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vpertj/skillguard/internal/analyzer"
	"github.com/vpertj/skillguard/internal/parser"
	"github.com/vpertj/skillguard/internal/report"
	"github.com/vpertj/skillguard/internal/rules"
	"github.com/vpertj/skillguard/internal/sandbox"
)

func main() {
	var (
		format         string
		jsonCompat     bool
		outFile        string
		rulesDir       string
		proRulesDir    string
		failThreshold  float64
		sandboxEnabled bool
	)
	auditCmd := &cobra.Command{
		Use:   "audit <path>",
		Short: "审计技能包（目录 / 单文件 / zip），输出风险报告",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonCompat && format == "md" {
				format = "json"
			}
			return runAudit(args[0], format, outFile, rulesDir, proRulesDir, failThreshold, sandboxEnabled)
		},
	}
	auditCmd.Flags().StringVarP(&format, "format", "f", "md", "输出格式：md | json | sarif（默认 md）")
	auditCmd.Flags().BoolVar(&jsonCompat, "json", false, "等价于 --format json（向后兼容）")
	auditCmd.Flags().StringVarP(&outFile, "output", "o", "", "输出到文件（默认 stdout）")
	auditCmd.Flags().StringVar(&rulesDir, "rules", "rules/rules.yaml", "公开规则库路径")
	auditCmd.Flags().StringVar(&proRulesDir, "pro-rules", "rules/pro-rules.yaml", "核心规则库路径（闭源，可缺失）")
	auditCmd.Flags().Float64Var(&failThreshold, "fail-threshold", 0, "评分超过该阈值时以非零退出（用于 CI 门禁；0 表示不启用）")
	auditCmd.Flags().BoolVar(&sandboxEnabled, "sandbox", false, "启用沙箱行为观察（当前为静态模拟后端，不真正执行代码）")

	rootCmd := &cobra.Command{Use: "skillguard", Short: "SkillGuard 技能安全审计工具"}
	rootCmd.AddCommand(auditCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func runAudit(path string, format string, outFile, rulesPath, proRulesPath string, failThreshold float64, sandboxEnabled bool) error {
	rs, err := rules.LoadRules(rulesPath, proRulesPath)
	if err != nil {
		return fmt.Errorf("加载规则库: %w", err)
	}
	files, root, err := parser.CollectFiles(path)
	if err != nil {
		return fmt.Errorf("采集技能包: %w", err)
	}
	// 仅 zip 输入会解压到独立临时目录，需要清理；目录/单文件输入 root 指向用户路径，绝不删除
	if strings.EqualFold(filepath.Ext(path), ".zip") {
		defer os.RemoveAll(root)
	}

	res, err := analyzer.Analyze(files, root, rs)
	if err != nil {
		return fmt.Errorf("审计执行: %w", err)
	}
	score := analyzer.Score(res.Findings)
	data := report.BuildReportData(res, score, path, rs.Meta())

	// 可选沙箱行为观察（feature flag，默认 off）：当前为静态模拟后端。
	// gVisor 后端就绪后通过 sandbox.SetDefaultBackend 替换，此处无需改动。
	if sandboxEnabled {
		srep, err := sandbox.Run(cmdContext(), root, sandbox.Config{NetworkOff: true})
		if err != nil {
			return fmt.Errorf("沙箱行为观察失败: %w", err)
		}
		data.Sandbox = toSandboxReport(srep)
	}

	var out []byte
	switch format {
	case "json":
		out, err = report.RenderJSON(data)
	case "sarif":
		out, err = report.RenderSARIF(data)
	case "md", "markdown", "":
		out = []byte(report.RenderMarkdown(data))
	default:
		return fmt.Errorf("未知输出格式 %q（可选 md | json | sarif）", format)
	}
	if err != nil {
		return err
	}
	if outFile != "" {
		if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil && filepath.Dir(outFile) != "." {
			return err
		}
		if err := os.WriteFile(outFile, out, 0o644); err != nil {
			return err
		}
	} else {
		fmt.Println(string(out))
	}

	// CI 门禁：写完报告后，若评分超过阈值则以非零退出（供 GitHub Action 拦截 PR）。
	if failThreshold > 0 && score.Score > failThreshold {
		return fmt.Errorf("评分 %.1f 超过阈值 %.1f（level=%s），门禁判定失败",
			score.Score, failThreshold, score.LevelKey)
	}
	return nil
}

// cmdContext 返回 CLI 的后台 context（供沙箱调用）。
func cmdContext() context.Context { return context.Background() }

// toSandboxReport 把 sandbox.Report 适配为 report.SandboxReport（保持 report 层不依赖 sandbox 包）。
func toSandboxReport(s *sandbox.Report) *report.SandboxReport {
	if s == nil {
		return nil
	}
	return &report.SandboxReport{
		Backend:            s.Backend,
		FileReads:          s.FileReads,
		FileWrites:         s.FileWrites,
		NetworkConnections: s.NetworkConnections,
		ProcessTree:        s.ProcessTree,
		EnvReads:           s.EnvReads,
		PVBehavior:         s.PVBehavior,
	}
}
