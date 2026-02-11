package core

import (
	"fmt"
	"os"
)

// CreateZ3Solver 创建 Z3 求解器实例
// 自动检测 Z3 是否可用，如果不可用则使用存根实现
func CreateZ3Solver() (Z3Solver, error) {
	return NewZ3Solver()
}

// IsZ3Available 检查 Z3 是否可用
func IsZ3Available() bool {
	solver, err := NewZ3Solver()
	if err != nil {
		return false
	}
	defer solver.Close()
	return solver.IsAvailable()
}

// CreateZ3SolverWithOptions 创建带选项的 Z3 求解器
func CreateZ3SolverWithOptions(options *Z3Options) (Z3Solver, error) {
	// 如果强制使用存根实现
	if options != nil && options.ForceStub {
		fmt.Printf("Forcing stub implementation as requested\n")
		os.Setenv("GOSAST_DISABLE_Z3", "1")
	}

	return CreateZ3Solver()
}

// GetZ3Version 获取 Z3 版本信息
func GetZ3Version() string {
	if IsZ3Available() {
		solver, _ := CreateZ3Solver()
		if solver != nil {
			defer solver.Close()
			return solver.String()
		}
	}
	return "Z3 Not Available"
}

// PrintZ3Status 打印 Z3 状态信息
func PrintZ3Status() {
	fmt.Printf("Z3 Status:\n")
	fmt.Printf("  Available: %v\n", IsZ3Available())

	if solver, err := CreateZ3Solver(); err == nil && solver != nil {
		defer solver.Close()
		stats := solver.GetSolverStats()
		for k, v := range stats {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}
}

// Z3Options Z3 求解器选项
type Z3Options struct {
	Timeout     int  // 超时时间（毫秒）
	EnableModel bool // 是否启用模型生成
	ForceStub   bool // 强制使用存根实现
	Verbose     bool // 详细输出
}