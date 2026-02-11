//go:build !noz3
// +build !noz3

package core

import (
	"fmt"
	"os"
)

// Z3SolverImpl 统一的 Z3 求解器实现
// 根据运行时条件决定使用实际 Z3 CGO 还是存根实现
type Z3SolverImpl struct {
	active bool
	cgo    interface{} // CGO 实现或 nil
	stats  map[string]interface{}
}

// NewZ3Solver 创建新的 Z3 求解器
func NewZ3Solver() (*Z3SolverImpl, error) {
	impl := &Z3SolverImpl{
		stats: make(map[string]interface{}),
	}

	// 检查是否禁用了 Z3
	if os.Getenv("GOSAST_DISABLE_Z3") != "" {
		fmt.Printf("Z3 disabled by GOSAST_DISABLE_Z3 environment variable\n")
		impl.active = false
		impl.stats["version"] = "Z3 Stub Implementation"
		impl.stats["available"] = false
		impl.stats["message"] = "Z3 disabled by environment variable"
		return impl, nil
	}

	// 检查 Z3 是否可用
	if !isZ3LibAvailable() {
		fmt.Printf("Z3 library not found, using stub implementation\n")
		impl.active = false
		impl.stats["version"] = "Z3 Stub Implementation"
		impl.stats["available"] = false
		impl.stats["message"] = "Z3 library not available"
		return impl, nil
	}

	// 尝试创建 CGO 版本的 Z3 求解器
	if cgoSolver, err := createZ3SolverCGO(); err == nil {
		impl.active = true
		impl.cgo = cgoSolver
		impl.stats["version"] = "Z3 CGO Active"
		impl.stats["available"] = true
		impl.stats["message"] = "Z3 CGO integration active"
		fmt.Printf("Z3 CGO solver initialized successfully\n")
	} else {
		fmt.Printf("Failed to create Z3 CGO solver, using stub: %v\n", err)
		impl.active = false
		impl.stats["version"] = "Z3 Stub Implementation"
		impl.stats["available"] = false
		impl.stats["message"] = "Z3 CGO initialization failed"
	}

	return impl, nil
}

// createZ3SolverCGO 创建 CGO 版本的 Z3 求解器
func createZ3SolverCGO() (interface{}, error) {
	// 尝试创建实际的 CGO 版本
	if !checkCGOSupport() {
		return nil, fmt.Errorf("CGO not supported on this platform")
	}

	// 创建 Z3SolverCGO 实例
	cgoSolver, err := NewZ3SolverCGO()
	if err != nil {
		return nil, fmt.Errorf("failed to create Z3 CGO solver: %v", err)
	}

	return cgoSolver, nil
}

// checkCGOSupport 检查 CGO 支持
func checkCGOSupport() bool {
	// 检查环境变量
	if os.Getenv("CGO_ENABLED") == "0" {
		return false
	}

	// 检查平台
	if os.Getenv("GOOS") == "js" {
		return false
	}

	return true
}

// CheckPathFeasibility 检查路径可行性
func (z *Z3SolverImpl) CheckPathFeasible(from, to interface{}) bool {
	if z.active && z.cgo != nil {
		// 使用 CGO Z3 实现
		if solver, ok := z.cgo.(interface{ CheckPathFeasible(from, to interface{}) bool }); ok {
			return solver.CheckPathFeasible(from, to)
		}
	}
	// 使用存根实现（fallback）
	return true
}

// CheckOverflow 检查整数溢出
func (z *Z3SolverImpl) CheckOverflow(lhs, rhs interface{}) bool {
	if z.active && z.cgo != nil {
		// 使用 CGO Z3 实现
		if solver, ok := z.cgo.(interface{ CheckOverflow(lhs, rhs interface{}) bool }); ok {
			return solver.CheckOverflow(lhs, rhs)
		}
	}
	// 使用存根实现（fallback）
	return false
}

// CheckUnderflow 检查整数下溢（无符号减法回绕）
func (z *Z3SolverImpl) CheckUnderflow(lhs, rhs interface{}) bool {
	if z.active && z.cgo != nil {
		// 使用 CGO Z3 实现
		if solver, ok := z.cgo.(interface{ CheckUnderflow(lhs, rhs interface{}) bool }); ok {
			return solver.CheckUnderflow(lhs, rhs)
		}
	}
	// 使用存根实现（fallback）
	// 对于存根实现，我们使用简单的启发式检查
	return checkUnderflowStub(lhs, rhs)
}

// checkUnderflowStub 存根实现的下溢检查
func checkUnderflowStub(lhs, rhs interface{}) bool {
	// 如果都是整数，可以进行简单检查
	if leftInt, ok := lhs.(int64); ok {
		if rightInt, ok := rhs.(int64); ok {
			// 对于无符号减法，如果 rhs > lhs 则会下溢
			// 这里我们保守地返回 true，表示可能下溢
			return rightInt > leftInt
		}
	}
	// 对于其他情况，返回 false（保守策略）
	return false
}

// Close 清理资源
func (z *Z3SolverImpl) Close() {
	if z.active && z.cgo != nil {
		// 清理 CGO Z3 资源
		if closer, ok := z.cgo.(interface{ Close() }); ok {
			closer.Close()
		}
		z.cgo = nil
	}
	z.active = false
}

// String 返回求解器的字符串表示
func (z *Z3SolverImpl) String() string {
	if z.active {
		return "Z3 Solver (Active)"
	}
	return "Z3 Solver (Stub)"
}

// GetSolverStats 获取求解器统计信息
func (z *Z3SolverImpl) GetSolverStats() map[string]interface{} {
	statsCopy := make(map[string]interface{})
	for k, v := range z.stats {
		statsCopy[k] = v
	}
	return statsCopy
}

// IsAvailable 检查 Z3 是否可用
func (z *Z3SolverImpl) IsAvailable() bool {
	return z.active
}

// === Z3 库检测 ===

// isZ3LibAvailable 检查 Z3 库是否可用
func isZ3LibAvailable() bool {
	// 首先检查环境变量
	if os.Getenv("GOSAST_FORCE_Z3_STUB") != "" {
		return false
	}

	// 检查常见的 Z3 库路径
	paths := []string{
		"/opt/homebrew/anaconda3/lib/libz3.dylib",
		"/opt/homebrew/lib/libz3.dylib",
		"/usr/local/lib/libz3.dylib",
		"/usr/lib/x86_64-linux-gnu/libz3.so",
		"/usr/lib/libz3.so",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("Found Z3 library at: %s\n", path)
			return true
		}
	}

	// 检查 pkg-config
	if os.Getenv("PKG_CONFIG_PATH") != "" {
		if _, err := os.Stat("/opt/homebrew/anaconda3/lib/pkgconfig/z3.pc"); err == nil {
			fmt.Printf("Found Z3 pkg-config file\n")
			return true
		}
	}

	// 简单检查：尝试使用环境变量
	if os.Getenv("Z3_ROOT") != "" || os.Getenv("LD_LIBRARY_PATH") != "" {
		return true // 假设设置正确
	}

	fmt.Printf("Z3 library not found in standard locations\n")
	return false
}

