package parser

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSkillMDWithFrontmatter(t *testing.T) {
	content := "---\nname: demo-skill\ndescription: 演示技能\nallowed-tools: [read_file, grep]\n---\n# 正文\n这是正文内容\n"
	fm, body, err := ParseSkillMD(content)
	if err != nil {
		t.Fatalf("ParseSkillMD: %v", err)
	}
	if fm.Name != "demo-skill" || fm.Description != "演示技能" {
		t.Errorf("fm = %+v", fm)
	}
	if len(fm.AllowedTools) != 2 || fm.AllowedTools[0] != "read_file" {
		t.Errorf("AllowedTools = %v", fm.AllowedTools)
	}
	if !strings.Contains(body, "# 正文") || strings.Contains(body, "name:") {
		t.Errorf("body = %q", body)
	}
}

func TestParseSkillMDWithoutFrontmatter(t *testing.T) {
	content := "# 纯正文\n没有 frontmatter\n"
	fm, body, err := ParseSkillMD(content)
	if err != nil {
		t.Fatalf("无 frontmatter 应容忍: %v", err)
	}
	if fm.Name != "" {
		t.Errorf("fm = %+v, want zero value", fm)
	}
	if body != content {
		t.Errorf("body = %q, want 全文", body)
	}
}

func TestParseSkillMDBrokenFrontmatter(t *testing.T) {
	if _, _, err := ParseSkillMD("---\nname: [broken\n---\nbody\n"); err == nil {
		t.Fatal("want error for broken yaml")
	}
	if _, _, err := ParseSkillMD("---\nname: x\n没有闭合\n"); err == nil {
		t.Fatal("want error for unclosed frontmatter")
	}
}

func TestCollectFilesDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "scripts", "sub"), 0o755)
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "scripts", "run.sh"), []byte("y"), 0o644)
	os.WriteFile(filepath.Join(dir, "scripts", "sub", "deep.py"), []byte("z"), 0o644)
	os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("git"), 0o644)

	files, root, err := CollectFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if root != dir {
		t.Errorf("root = %q, want %q", root, dir)
	}
	if len(files) != 3 {
		t.Errorf("files = %v, want 3 个（.git 应被跳过）", files)
	}
	if len(FindSkillMD(files)) != 1 || FindSkillMD(files)[0] != "SKILL.md" {
		t.Errorf("FindSkillMD = %v", FindSkillMD(files))
	}
}

func TestCollectFilesSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.sh")
	os.WriteFile(path, []byte("x"), 0o644)
	files, root, err := CollectFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "run.sh" {
		t.Errorf("files = %v", files)
	}
	if root != dir {
		t.Errorf("root = %q, want %q", root, dir)
	}
}

func TestCollectFilesZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "skill.zip")
	f, _ := os.Create(zipPath)
	w := zip.NewWriter(f)
	for name, content := range map[string]string{
		"SKILL.md":       "---\nname: z\n---\nbody",
		"scripts/run.sh": "#!/bin/sh\necho hi",
		"../evil/escape": "zip slip",
	} {
		ww, _ := w.Create(name)
		ww.Write([]byte(content))
	}
	w.Close()
	f.Close()

	files, root, err := CollectFiles(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if len(files) != 2 {
		t.Errorf("files = %v, want 2（zip slip 条目应被拒绝）", files)
	}
	for _, name := range files {
		if strings.Contains(name, "..") {
			t.Errorf("非法路径泄漏: %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "SKILL.md")); err != nil {
		t.Errorf("解压后 SKILL.md 不存在: %v", err)
	}
}

func TestIsScannable(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.txt")
	os.WriteFile(big, make([]byte, MaxFileSize+1), 0o644)
	if IsScannable(big, MaxFileSize+1) {
		t.Error("超 2MB 应不可扫描")
	}
	if IsScannable(filepath.Join(dir, "a.png"), 100) {
		t.Error(".png 应不可扫描")
	}
	if !IsScannable(filepath.Join(dir, "a.sh"), 100) {
		t.Error(".sh 应可扫描")
	}
	bin := filepath.Join(dir, "bin.dat")
	os.WriteFile(bin, []byte{0x41, 0x00, 0x42}, 0o644)
	if IsScannable(bin, 3) {
		t.Error("含 NUL 字节应视为二进制")
	}
}

func TestFindSkillMDCaseInsensitive(t *testing.T) {
	got := FindSkillMD([]string{"a/skill.md", "b/README.md", "c/SKILL.MD"})
	if len(got) != 2 {
		t.Errorf("FindSkillMD = %v, want 2", got)
	}
}
