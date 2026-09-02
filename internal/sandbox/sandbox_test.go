package sandbox

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// testdata 复用 analyzer 的真实技能包样本（正例含恶意脚本，反例为良性包）。
var (
	maliciousDir = filepath.Join("..", "analyzer", "testdata", "malicious-skill")
	benignDir    = filepath.Join("..", "analyzer", "testdata", "benign-skill")
)

func TestStaticSimulatorMalicious(t *testing.T) {
	ctx := context.Background()
	rep, err := Run(ctx, maliciousDir, Config{NetworkOff: true})
	if err != nil {
		t.Fatalf("Run 失败: %v", err)
	}

	// 正例：恶意包应提取出网络外联行为（curl/URL）与进程调用（curl|bash 管道）。
	if len(rep.NetworkConnections) == 0 {
		t.Error("恶意样本应提取到网络外联行为，实际为空")
	}
	hasEvil := false
	for _, n := range rep.NetworkConnections {
		if n == "http://evil.example.com/x.sh" || n == "http://evil.example.com/collect" {
			hasEvil = true
		}
	}
	if !hasEvil {
		t.Errorf("恶意样本应提取到 evil.example.com 外联目标，实际: %v", rep.NetworkConnections)
	}

	if len(rep.ProcessTree) == 0 {
		t.Error("恶意样本应提取到进程调用行为（curl|bash），实际为空")
	}
	if rep.PVBehavior == "" {
		t.Error("含可执行脚本的包应标注 PVBehavior")
	}
}

func TestStaticSimulatorBenign(t *testing.T) {
	ctx := context.Background()
	rep, err := Run(ctx, benignDir, Config{NetworkOff: true})
	if err != nil {
		t.Fatalf("Run 失败: %v", err)
	}

	// 反例：良性包不应出现网络外联/危险进程调用。
	for _, n := range rep.NetworkConnections {
		if n != "" {
			t.Errorf("良性样本不应有网络外联，实际有 %q", n)
		}
	}
	if rep.ExitCode != 0 {
		t.Errorf("静态模拟不执行代码，ExitCode 应为 0，实际 %d", rep.ExitCode)
	}
}

func TestStaticSimulatorZIP(t *testing.T) {
	// zip 输入应走解压→提取→清理路径且不报错。用现成技能包打成 zip 验证。
	// 为保持测试轻量，用单 zip 包路径（若 testdata 无 zip 则跳过）。
	dir := filepath.Join("..", "analyzer", "testdata", "malicious-skill")
	zipPath := filepath.Join(t.TempDir(), "mal.zip")
	if err := zipDir(dir, zipPath); err != nil {
		t.Fatalf("打包测试样本失败: %v", err)
	}
	ctx := context.Background()
	rep, err := Run(ctx, zipPath, Config{})
	if err != nil {
		t.Fatalf("zip 输入 Run 失败: %v", err)
	}
	if len(rep.NetworkConnections) == 0 {
		t.Errorf("zip 输入应提取到网络外联行为，实际为空")
	}
}

func TestCaptureMatches(t *testing.T) {
	// fileReadRe 应捕获文件名（组1优先），无捕获组时取完整匹配。
	got := captureMatches(fileReadRe, `data = open("/etc/passwd").read()`)
	if len(got) != 1 || got[0] != "/etc/passwd" {
		t.Errorf("captureMatches(fileReadRe) = %v, want [\"/etc/passwd\"]", got)
	}
	// processRe 无捕获组，取完整匹配片段。
	got = captureMatches(processRe, `subprocess.run(["bash","-c",cmd])`)
	if len(got) != 1 {
		t.Errorf("captureMatches(processRe) 应为 1 条，实际 %d (%v)", len(got), got)
	}
}

// zipDir 把目录递归打成 zip 文件（测试用，路径相对根）。
func zipDir(srcDir, dest string) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	return filepath.WalkDir(srcDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
}
