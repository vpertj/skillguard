// Package sandbox 沙箱动态执行器：对技能包做行为观察（文件/网络/进程/环境变量）。
//
// 当前阶段为"接口骨架 + 静态模拟后端"（StaticSimulator），gVisor 作为可插拔后端预留。
// 沙箱是审计流水线的可选阶段（feature flag，默认 off，ARCHITECTURE §4.2），
// 用于补充静态规则/AST/LLM 无法覆盖的"运行时到底做了什么"。
package sandbox

import (
	"context"
	"time"
)

// Config 沙箱运行配置（ARCHITECTURE §5.8）。
type Config struct {
	NetworkOff bool          // 默认 true（断网）
	DecoyCreds bool          // 内置假 ~/.ssh/id_rsa、假 .env
	Timeout    time.Duration // 默认 30s
	CPULimit   string        // 如 "1" 、"500m"
	MemLimit   string        // 如 "256M"
}

// Report 行为观察结果（ARCHITECTURE §5.8）。
type Report struct {
	Backend            string   // 产生本报告的后端名（static / gvisor）
	FileReads          []string // 读取的文件路径
	FileWrites         []string // 写入的文件路径
	NetworkConnections []string // 外联目标（host:port / URL）
	ProcessTree        []string // 启动的进程（含命令行参数）
	EnvReads           []string // 读取的环境变量名
	ExitCode           int      // 退出码（0 正常）
	// PVBehavior 是可选的"潜在行为"摘要（静态后端注入，用于说明性输出）。
	PVBehavior string
}

// Backend 沙箱底层实现抽象：gVisor（未来）与 StaticSimulator（当前）都实现此接口。
// 通过接口隔离，新增后端无需改动上游调用方。
type Backend interface {
	// Name 后端名（"static" / "gvisor"），用于报告标注与降级日志。
	Name() string
	// Run 对 packagePath 指向的技能包执行行为观察，返回观察报告。
	Run(ctx context.Context, packagePath string, cfg Config) (*Report, error)
}

// defaultBackend 当前默认后端（静态模拟器）。gVisor 上线后可切换。
var defaultBackend Backend = &StaticSimulator{}

// Run 沙箱统一入口：对 packagePath 指向的技能包做行为观察。
// 默认使用 StaticSimulator；可通过 RunWithBackend 指定其它后端（如 gVisor）。
func Run(ctx context.Context, packagePath string, cfg Config) (*Report, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return defaultBackend.Run(ctx, packagePath, cfg)
}

// RunWithBackend 使用指定后端执行（供测试与 gVisor 后端接入）。
func RunWithBackend(ctx context.Context, packagePath string, cfg Config, backend Backend) (*Report, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return backend.Run(ctx, packagePath, cfg)
}

// SetDefaultBackend 设置默认后端（启动时从配置注入；gVisor 就绪后调用）。
func SetDefaultBackend(b Backend) {
	defaultBackend = b
}
