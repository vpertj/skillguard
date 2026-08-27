// cmd/bench 是 SkillGuard 引擎基准测试工具：
// 对恶意/良性技能样本集跑引擎，输出检出率、误报率、耗时基线。
//
// 用法:
//
//	go run ./cmd/bench
//	go run ./cmd/bench --malicious-dir 自定义路径 --benign-dir 自定义路径
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tianjun/skillguard/internal/analyzer"
	"github.com/tianjun/skillguard/internal/llm"
	"github.com/tianjun/skillguard/internal/parser"
	"github.com/tianjun/skillguard/internal/rules"
)

type sampleResult struct {
	Name     string
	Score    float64
	Grade    string
	Findings int
	Dur      time.Duration
	Err      error
	// LLM 二次裁决统计
	Rejected int // 被判误报移除的命中数
	LLMScore float64
}

func main() {
	malDir := flag.String("malicious-dir", "internal/bench/testdata/malicious", "恶意样本目录（每个子目录一个技能包）")
	benDir := flag.String("benign-dir", "internal/bench/testdata/benign", "良性样本目录（每个子目录一个技能包）")
	rulesPath := flag.String("rules", "rules/rules.yaml", "规则库路径")
	llmMode := flag.Bool("llm", false, "启用 LLM 二次裁决（需 DEEPSEEK_API_KEY）")
	flag.Parse()

	rs, err := rules.LoadRules(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载规则库失败: %v\n", err)
		os.Exit(1)
	}

	var rp llm.ReviewProvider
	if *llmMode {
		key := os.Getenv("DEEPSEEK_API_KEY")
		if key == "" {
			fmt.Fprintln(os.Stderr, "--llm 需要 DEEPSEEK_API_KEY 环境变量")
			os.Exit(1)
		}
		rp, err = llm.NewDeepSeek(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "初始化 LLM 失败: %v\n", err)
			os.Exit(1)
		}
	}

	mal := runSet(*malDir, rs, rp)
	ben := runSet(*benDir, rs, rp)

	report(mal, ben, rp != nil, len(rs.Rules()))
}

// runSet 对目录下每个子目录（技能包）跑引擎。
func runSet(dir string, rs *rules.RuleSet, rp llm.ReviewProvider) []sampleResult {
	var out []sampleResult
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取样本目录 %s 失败: %v\n", dir, err)
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkg := filepath.Join(dir, e.Name())
		res := sampleResult{Name: e.Name()}
		start := time.Now()
		files, root, err := parser.CollectFiles(pkg)
		if err != nil {
			res.Err = fmt.Errorf("collect: %w", err)
		} else {
			ar, err := analyzer.Analyze(files, root, rs)
			if err != nil {
				res.Err = fmt.Errorf("analyze: %w", err)
			} else {
				score := analyzer.Score(ar.Findings)
				_, grade, _ := analyzer.Grade(score.Score)
				res.Score = score.Score
				res.Grade = grade
				res.Findings = len(ar.Findings)
				res.LLMScore = res.Score

				// LLM 二次裁决：有命中时复核，误报移除后重评分
				if rp != nil && len(ar.Findings) > 0 {
					revReq := llm.ReviewRequest{
						SkillBody: skillBodyOf(ar),
						Findings:  toReviewInputs(ar.Findings),
					}
					revRes, err := rp.ReviewFindings(context.Background(), revReq)
					if err == nil && len(revRes.Reviews) > 0 {
						kept, rejected := analyzer.ApplyReview(ar.Findings, revRes.Reviews)
						res.Rejected = len(rejected)
						revScore := analyzer.Score(kept)
						res.LLMScore = revScore.Score
					}
				}
			}
		}
		res.Dur = time.Since(start)
		out = append(out, res)
	}
	return out
}

// skillBodyOf 取 SKILL.md 正文预览作为 LLM 上下文。
func skillBodyOf(ar *analyzer.Result) string {
	if ar.SkillMD != nil {
		return ar.SkillMD.BodyPreview
	}
	return ""
}

// toReviewInputs 静态命中 → 裁决输入。
func toReviewInputs(findings []analyzer.Finding) []llm.ReviewFindingInput {
	out := make([]llm.ReviewFindingInput, 0, len(findings))
	for _, f := range findings {
		out = append(out, llm.ReviewFindingInput{
			RuleID: f.RuleID, File: f.File, Snippet: f.Snippet,
		})
	}
	return out
}

// report 输出基线与明细。
func report(mal, ben []sampleResult, llmMode bool, ruleCount int) {
	// 安全等级：score ≤ 20 才算"未检出"
	isSafe := func(s sampleResult) bool { return s.Score <= 20 }

	malDetected := 0
	for _, s := range mal {
		if !isSafe(s) {
			malDetected++
		}
	}
	benSafe := 0
	for _, s := range ben {
		if isSafe(s) {
			benSafe++
		}
	}

	malRate := 0.0
	if len(mal) > 0 {
		malRate = float64(malDetected) / float64(len(mal)) * 100
	}
	benRate := 0.0
	if len(ben) > 0 {
		benRate = float64(len(ben)-benSafe) / float64(len(ben)) * 100
	}
	avgDur := avgDuration(append(mal, ben...))

	fmt.Println("==========================================")
	fmt.Println(" SkillGuard 引擎基准（基线报告）")
	fmt.Println("==========================================")
	fmt.Printf("规则库:      %d 条规则\n", ruleCount)
	fmt.Printf("恶意样本:    %d 个\n", len(mal))
	fmt.Printf("良性样本:    %d 个\n", len(ben))
	if llmMode {
		fmt.Println("模式:       静态 + LLM 二次裁决")
	}
	fmt.Println("------------------------------------------")
	fmt.Printf("恶意检出率:  %.1f%%  (%d/%d)   [目标 ≥85%%]\n", malRate, malDetected, len(mal))
	fmt.Printf("良性误报率:  %.1f%%  (%d/%d)   [目标 ≤15%%]\n", benRate, len(ben)-benSafe, len(ben))
	fmt.Printf("平均耗时:    %s\n", avgDur.Round(time.Millisecond))
	if llmMode {
		llmBenRate := reviewBenRate(ben)
		llmMalRate := reviewMalRate(mal)
		fmt.Println("------------------------------------------")
		fmt.Printf("[LLM 裁决后] 恶意检出率: %.1f%%  误报率: %.1f%%\n", llmMalRate, llmBenRate)
		rejected := 0
		for _, s := range append(mal, ben...) {
			rejected += s.Rejected
		}
		fmt.Printf("[LLM 裁决]   共移除误报命中 %d 条\n", rejected)
	}
	fmt.Println("------------------------------------------")
	fmt.Println("分级分布（恶意样本）:")
	printGradeDist(mal)
	fmt.Println("------------------------------------------")
	fmt.Println("漏检清单（恶意样本被判安全 ≤20 分）:")
	printMisses(mal)
	fmt.Println("------------------------------------------")
	fmt.Println("误报清单（良性样本被判非安全 >20 分）:")
	printFalsePositives(ben)
	fmt.Println("==========================================")
}

// reviewBenRate LLM 裁决后的良性误报率（用 LLMScore 判断）。
func reviewBenRate(ben []sampleResult) float64 {
	n := 0
	for _, s := range ben {
		if s.LLMScore > 20 {
			n++
		}
	}
	if len(ben) == 0 {
		return 0
	}
	return float64(n) / float64(len(ben)) * 100
}

// reviewMalRate LLM 裁决后的恶意检出率。
func reviewMalRate(mal []sampleResult) float64 {
	n := 0
	for _, s := range mal {
		if s.LLMScore > 20 {
			n++
		}
	}
	if len(mal) == 0 {
		return 0
	}
	return float64(n) / float64(len(mal)) * 100
}

func avgDuration(samples []sampleResult) time.Duration {
	var total time.Duration
	for _, s := range samples {
		total += s.Dur
	}
	if len(samples) == 0 {
		return 0
	}
	return total / time.Duration(len(samples))
}

func printGradeDist(mal []sampleResult) {
	dist := map[string]int{}
	for _, s := range mal {
		dist[s.Grade]++
	}
	keys := make([]string, 0, len(dist))
	for k := range dist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-8s %d\n", k, dist[k])
	}
}

func printMisses(mal []sampleResult) {
	n := 0
	for _, s := range mal {
		if s.Score <= 20 {
			fmt.Printf("  ✗ %-40s score=%.1f findings=%d err=%v\n", s.Name, s.Score, s.Findings, s.Err)
			n++
		}
	}
	if n == 0 {
		fmt.Println("  （无漏检）")
	}
}

func printFalsePositives(ben []sampleResult) {
	n := 0
	for _, s := range ben {
		if s.Score > 20 {
			fmt.Printf("  ✗ %-40s score=%.1f grade=%s findings=%d\n", s.Name, s.Score, s.Grade, s.Findings)
			n++
		}
	}
	if n == 0 {
		fmt.Println("  （无误报）")
	}
}
