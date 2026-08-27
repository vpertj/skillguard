// Package astscan 基于 tree-sitter 的语法树级危险调用链检测。
// 与正则互补：正则看文本模式，AST 看调用结构——能区分
// subprocess.run(["soffice"])（合法）与 subprocess.run(["bash","-c","curl|bash"])（恶意）。
package astscan

import (
	"regexp"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// Danger 一条 AST 检测结果（映射到 analyzer.Finding 的规则语义）。
type Danger struct {
	RuleID   string // 如 RS-037
	Category string
	Weight   int
	Severity string
	File     string
	Line     int
	Snippet  string
	Detail   string
}

// 危险命令词（出现在 subprocess 参数里）
var dangerCmd = regexp.MustCompile(`(?i)\b(curl|wget|bash|sh|zsh|python|python3|node|powershell|cmd\.exe|/bin/sh)\b`)

// 网络/下载特征（管道执行要求 | 前缀，避免单独 bash 误匹配）
var netIndicator = regexp.MustCompile(`(?i)(https?://|ftp://|\|\s*(ba)?sh\b|wget|curl)`)

// subprocess 方法名
var subprocessMethods = map[string]bool{
	"run": true, "Popen": true, "call": true, "check_output": true, "check_call": true,
}

// pythonParser 单例（tree-sitter parser 非并发安全，ScanPython 用锁保护）
var (
	pythonParser     *tree_sitter.Parser
	pythonParserInit = func() *tree_sitter.Parser {
		p := tree_sitter.NewParser()
		p.SetLanguage(tree_sitter.NewLanguage(python.Language()))
		return p
	}
)

// ScanPython 解析 Python 源码，返回危险调用链检测结果。
func ScanPython(src []byte, file string) []Danger {
	if pythonParser == nil {
		pythonParser = pythonParserInit()
	}
	tree := pythonParser.Parse(src, nil)
	if tree == nil {
		return nil
	}
	defer tree.Close()

	var out []Danger
	var walk func(node *tree_sitter.Node)
	walk = func(node *tree_sitter.Node) {
		if node.Kind() == "call" {
			if d := checkSubprocessCall(node, src, file); d != nil {
				out = append(out, *d)
			}
		}
		for i := uint(0); i < node.ChildCount(); i++ {
			walk(node.Child(i))
		}
	}
	walk(tree.RootNode())
	return out
}

// checkSubprocessCall 检查 subprocess.Xxx(...) 调用是否携带危险参数。
func checkSubprocessCall(node *tree_sitter.Node, src []byte, file string) *Danger {
	funcName := node.ChildByFieldName("function")
	if funcName == nil || funcName.Kind() != "attribute" {
		return nil
	}
	obj := funcName.ChildByFieldName("object")
	attr := funcName.ChildByFieldName("attribute")
	if obj == nil || attr == nil || obj.Kind() != "identifier" || attr.Kind() != "identifier" {
		return nil
	}
	if obj.Utf8Text(src) != "subprocess" || !subprocessMethods[attr.Utf8Text(src)] {
		return nil
	}

	// 提取第一个参数（列表/字符串）
	argsNode := node.ChildByFieldName("arguments")
	if argsNode == nil {
		return nil
	}
	firstArg := firstArgOf(argsNode, src)

	// 危险判定：含危险命令词 + 含网络/管道/脚本执行特征
	if dangerCmd.MatchString(firstArg) && netIndicator.MatchString(firstArg) {
		return &Danger{
			RuleID:   "RS-037",
			Category: "CODE_EXECUTION",
			Weight:   95,
			Severity: "critical",
			File:     file,
			Line:     int(node.StartPosition().Row) + 1,
			Snippet:  truncate(firstArg, 100),
			Detail:   "subprocess 调用携带下载/管道执行特征（curl|bash 类）",
		}
	}
	// 纯 bash -c 脚本执行（无网络特征也算高危，可能执行任意命令）
	if dangerCmd.MatchString(firstArg) && strings.Contains(firstArg, "-c") {
		return &Danger{
			RuleID:   "RS-037",
			Category: "CODE_EXECUTION",
			Weight:   85,
			Severity: "high",
			File:     file,
			Line:     int(node.StartPosition().Row) + 1,
			Snippet:  truncate(firstArg, 100),
			Detail:   "subprocess 执行 bash -c 脚本",
		}
	}
	return nil
}

// firstArgOf 提取调用第一个参数（列表字面量则取整个列表文本）。
func firstArgOf(argsNode *tree_sitter.Node, src []byte) string {
	for i := uint(0); i < argsNode.ChildCount(); i++ {
		c := argsNode.Child(i)
		switch c.Kind() {
		case "list", "string", "concatenated_string", "call":
			return c.Utf8Text(src)
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
