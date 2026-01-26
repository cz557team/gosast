package core

import (
	"fmt"
	"runtime"
	"strings"
)

// ProjectScale 项目规模
type ProjectScale int

const (
	Small ProjectScale = iota
	Medium
	Large
	XLarge
)

// AutoConfig 自动配置生成器
type AutoConfig struct {
	hardware HardwareInfo
	project  ProjectInfo
}

// HardwareInfo 硬件信息
type HardwareInfo struct {
	CPUCores     int
	MemoryGB     int
	IsSSD        bool
	NetworkSpeed string // "1g", "10g", "25g", "100g"
}

// ProjectInfo 项目信息
type ProjectInfo struct {
	FileCount    int
	LineCount    int
	HasTests     bool
	IsDistributed bool
	MaxFileSize  int64 // bytes
}

// LargeProjectConfig 大型项目配置
type LargeProjectConfig struct {
	// 缓存配置
	CacheSize      int           // 缓存条目数
	MaxMemory      int64         // 最大内存使用(字节)
	EnableLRU      bool          // 启用LRU淘汰

	// 并发配置
	Workers        int           // 工作协程数
	QueueSize      int           // 任务队列大小
	SemaphoreSize  int           // 信号量大小

	// 扫描配置
	BatchSize      int           // 批处理大小
	EnablePreload  bool          // 启用预加载
	EnableMonitor  bool          // 启用性能监控
	EarlyExit      bool          // 启用早停
	SkipProcessed  bool          // 跳过已处理文件

	// 文件过滤
	MaxFileSize    int64         // 最大文件大小
	ExcludeLarge   bool          // 排除大文件
	ExcludeTest    bool          // 排除测试文件
	Incremental    bool          // 增量分析

	// 内存优化
	ObjectPools    bool          // 启用对象池
	PrewarmPools   bool          // 预热对象池
	GCThreshold    int64         // GC阈值

	// 分布式配置
	Distributed    bool          // 启用分布式
	NodeCount      int           // 节点数
	ShardSize      int           // 分片大小
}

// NewAutoConfig 创建自动配置生成器
func NewAutoConfig() *AutoConfig {
	return &AutoConfig{
		hardware: detectHardware(),
		project:  ProjectInfo{},
	}
}

// SetProjectInfo 设置项目信息
func (ac *AutoConfig) SetProjectInfo(fileCount, lineCount int, hasTests bool) *AutoConfig {
	ac.project.FileCount = fileCount
	ac.project.LineCount = lineCount
	ac.project.HasTests = hasTests
	return ac
}

// DetectProjectScale 检测项目规模
func (ac *AutoConfig) DetectProjectScale() ProjectScale {
	fileCount := ac.project.FileCount

	switch {
	case fileCount < 1000:
		return Small
	case fileCount < 10000:
		return Medium
	case fileCount < 100000:
		return Large
	default:
		return XLarge
	}
}

// GenerateConfig 生成配置
func (ac *AutoConfig) GenerateConfig() *LargeProjectConfig {
	scale := ac.DetectProjectScale()

	config := &LargeProjectConfig{
		EnableLRU:      true,
		EnableMonitor:  true,
		ObjectPools:    true,
		PrewarmPools:   true,
		EnablePreload:  true,
		MaxFileSize:    5 * 1024 * 1024, // 5MB默认
		ExcludeLarge:   true,
	}

	switch scale {
	case Small:
		config = ac.generateSmallConfig()
	case Medium:
		config = ac.generateMediumConfig()
	case Large:
		config = ac.generateLargeConfig()
	case XLarge:
		config = ac.generateXLargeConfig()
	}

	return config
}

// generateSmallConfig 生成小型项目配置
func (ac *AutoConfig) generateSmallConfig() *LargeProjectConfig {
	cpuCores := ac.hardware.CPUCores
	memoryGB := ac.hardware.MemoryGB

	return &LargeProjectConfig{
		// 缓存配置
		CacheSize:      min(1000, cpuCores*250),
		MaxMemory:      int64(memoryGB) * 200 * 1024 * 1024 / 10, // 20%内存
		EnableLRU:      true,

		// 并发配置
		Workers:        max(4, cpuCores),
		QueueSize:      500,
		SemaphoreSize:  max(4, cpuCores),

		// 扫描配置
		BatchSize:      100,
		EnablePreload:  true,
		EnableMonitor:  true,
		EarlyExit:      false,
		SkipProcessed:  false,

		// 文件过滤
		MaxFileSize:    1024 * 1024, // 1MB
		ExcludeLarge:   true,
		ExcludeTest:    false,
		Incremental:    false,

		// 内存优化
		ObjectPools:    true,
		PrewarmPools:   false,
		GCThreshold:    50 * 1024 * 1024, // 50MB

		// 分布式配置
		Distributed:    false,
	}
}

// generateMediumConfig 生成中型项目配置
func (ac *AutoConfig) generateMediumConfig() *LargeProjectConfig {
	cpuCores := ac.hardware.CPUCores
	memoryGB := ac.hardware.MemoryGB

	return &LargeProjectConfig{
		// 缓存配置
		CacheSize:      min(5000, cpuCores*400),
		MaxMemory:      int64(memoryGB) * 500 * 1024 * 1024 / 10, // 50%内存
		EnableLRU:      true,

		// 并发配置
		Workers:        min(16, cpuCores*2),
		QueueSize:      2000,
		SemaphoreSize:  min(16, cpuCores*2),

		// 扫描配置
		BatchSize:      500,
		EnablePreload:  true,
		EnableMonitor:  true,
		EarlyExit:      false,
		SkipProcessed:  true,

		// 文件过滤
		MaxFileSize:    2 * 1024 * 1024, // 2MB
		ExcludeLarge:   true,
		ExcludeTest:    ac.project.HasTests,
		Incremental:    true,

		// 内存优化
		ObjectPools:    true,
		PrewarmPools:   true,
		GCThreshold:    100 * 1024 * 1024, // 100MB

		// 分布式配置
		Distributed:    false,
	}
}

// generateLargeConfig 生成大型项目配置
func (ac *AutoConfig) generateLargeConfig() *LargeProjectConfig {
	cpuCores := ac.hardware.CPUCores
	memoryGB := ac.hardware.MemoryGB

	return &LargeProjectConfig{
		// 缓存配置
		CacheSize:      min(20000, cpuCores*800),
		MaxMemory:      int64(memoryGB) * 1024 * 1024 * 1024 / 2, // 50%内存
		EnableLRU:      true,

		// 并发配置
		Workers:        min(32, cpuCores*2),
		QueueSize:      10000,
		SemaphoreSize:  min(32, cpuCores*2),

		// 扫描配置
		BatchSize:      1000,
		EnablePreload:  true,
		EnableMonitor:  true,
		EarlyExit:      false,
		SkipProcessed:  true,

		// 文件过滤
		MaxFileSize:    5 * 1024 * 1024, // 5MB
		ExcludeLarge:   true,
		ExcludeTest:    ac.project.HasTests,
		Incremental:    true,

		// 内存优化
		ObjectPools:    true,
		PrewarmPools:   true,
		GCThreshold:    200 * 1024 * 1024, // 200MB

		// 分布式配置
		Distributed:    memoryGB >= 32, // 32GB+内存才启用
		NodeCount:      0,
		ShardSize:      5000,
	}
}

// generateXLargeConfig 生成超大型项目配置
func (ac *AutoConfig) generateXLargeConfig() *LargeProjectConfig {
	cpuCores := ac.hardware.CPUCores
	memoryGB := ac.hardware.MemoryGB

	config := &LargeProjectConfig{
		// 缓存配置
		CacheSize:      min(50000, cpuCores*1000),
		MaxMemory:      int64(memoryGB) * 3 * 1024 * 1024 * 1024 / 4, // 75%内存
		EnableLRU:      true,

		// 并发配置
		Workers:        min(64, cpuCores*3),
		QueueSize:      50000,
		SemaphoreSize:  min(64, cpuCores*3),

		// 扫描配置
		BatchSize:      2000,
		EnablePreload:  true,
		EnableMonitor:  true,
		EarlyExit:      false,
		SkipProcessed:  true,

		// 文件过滤
		MaxFileSize:    10 * 1024 * 1024, // 10MB
		ExcludeLarge:   true,
		ExcludeTest:    ac.project.HasTests,
		Incremental:    true,

		// 内存优化
		ObjectPools:    true,
		PrewarmPools:   true,
		GCThreshold:    500 * 1024 * 1024, // 500MB

		// 分布式配置
		Distributed:    memoryGB >= 64, // 64GB+内存启用分布式
	}

	if config.Distributed {
		config.NodeCount = max(2, memoryGB/32) // 每32GB一个节点
		config.ShardSize = ac.project.FileCount / config.NodeCount
	}

	return config
}

// detectHardware 检测硬件信息
func detectHardware() HardwareInfo {
	return HardwareInfo{
		CPUCores:     runtime.NumCPU(),
		MemoryGB:     estimateMemoryGB(),
		IsSSD:        detectSSD(),
		NetworkSpeed: "10g", // 默认万兆
	}
}

// estimateMemoryGB 估算内存大小
func estimateMemoryGB() int {
	// 这里应该使用系统调用获取真实内存大小
	// 简化实现，返回估算值
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// 估算系统总内存
	totalMem := mem.Sys / (1024 * 1024) // 转换为MB
	return int(totalMem / 1024) // 转换为GB
}

// detectSSD 检测是否为SSD
func detectSSD() bool {
	// 简化实现，假设现代系统都是SSD
	return true
}

// PrintConfig 打印配置
func (config *LargeProjectConfig) PrintConfig() {
	fmt.Println("=== 大型项目配置 ===")





	if config.Distributed {
	}
}

// String 返回配置的字符串表示
func (config *LargeProjectConfig) String() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Workers=%d", config.Workers))
	b.WriteString(fmt.Sprintf(" CacheSize=%d", config.CacheSize))
	b.WriteString(fmt.Sprintf(" MaxMemory=%dMB", config.MaxMemory/1024/1024))
	b.WriteString(fmt.Sprintf(" QueueSize=%d", config.QueueSize))

	if config.SkipProcessed {
		b.WriteString(" SkipProcessed=true")
	}
	if config.Incremental {
		b.WriteString(" Incremental=true")
	}
	if config.Distributed {
		b.WriteString(fmt.Sprintf(" Distributed=true Nodes=%d", config.NodeCount))
	}

	return b.String()
}

// ApplyToScanner 将配置应用到扫描器
func (config *LargeProjectConfig) ApplyToScanner(scanner *OptimizedScanner) {
	scanner.workers = config.Workers
	scanner.maxMemory = config.MaxMemory
	scanner.skipProcessed = config.SkipProcessed
	scanner.earlyExit = config.EarlyExit
}

// GetRecommendedConfig 获取推荐配置
func GetRecommendedConfig(scale ProjectScale, cpuCores, memoryGB int) *LargeProjectConfig {
	ac := &AutoConfig{
		hardware: HardwareInfo{
			CPUCores:  cpuCores,
			MemoryGB:  memoryGB,
		},
	}

	// 根据规模设置项目信息
	switch scale {
	case Small:
		ac.project = ProjectInfo{FileCount: 500}
	case Medium:
		ac.project = ProjectInfo{FileCount: 5000}
	case Large:
		ac.project = ProjectInfo{FileCount: 50000}
	case XLarge:
		ac.project = ProjectInfo{FileCount: 200000}
	}

	return ac.GenerateConfig()
}

// 辅助函数
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
