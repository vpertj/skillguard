// Command audit 提供 SkillGuard CLI：本地审计技能包（目录/单文件/zip）。
// 与 Web API 共用同一引擎内核，是私有化/企业自托管形态。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vpertj/skillguard/internal/analyzer"
	"github.com/vpertj/skillguard/internal/parser"
	"github.com/vpertj/skillguard/internal/report"
	"github.com/vpertj/skillguard/internal/rules"
)

func main() {
	var (
		jsonOut     bool
		outFile     string
		rulesDir    string
		proRulesDir string
	)
	auditCmd := &cobra.Command{
		Use:   "audit <path>",
		Short: "审计技能包（目录 / 单文件 / zip），输出风险报告",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAudit(args[0], jsonOut, outFile, rulesDir, proRulesDir)
		},
	}
	auditCmd.Flags().BoolVar(&jsonOut, "json", false, "输出 JSON 报告（默认 Markdown）")
	auditCmd.Flags().StringVarP(&outFile, "output", "o", "", "输出到文件（默认 stdout）")
	auditCmd.Flags().StringVar(&rulesDir, "rules", "rules/rules.yaml", "公开规则库路径")
	auditCmd.Flags().StringVar(&proRulesDir, "pro-rules", "rules/pro-rules.yaml", "核心规则库路径（闭源，可缺失）")

	rootCmd := &cobra.Command{Use: "skillguard", Short: "SkillGuard 技能安全审计工具"}
	rootCmd.AddCommand(auditCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func runAudit(path string, jsonOut bool, outFile, rulesPath, proRulesPath string) error {
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

	var out []byte
	if jsonOut {
		out, err = report.RenderJSON(data)
	} else {
		out = []byte(report.RenderMarkdown(data))
	}
	if err != nil {
		return err
	}
	if outFile != "" {
		if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil && filepath.Dir(outFile) != "." {
			return err
		}
		return os.WriteFile(outFile, out, 0o644)
	}
	fmt.Println(string(out))
	return nil
}
