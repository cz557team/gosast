//go:build noz3
// +build noz3

package core

import (
	"fmt"
	"os"
	"strconv"
)

// Z3SolverImpl 统一的 Z3 求解器实现（存根版本）
// 当使用 noz3 标签时使用存根实现
type Z3SolverImpl struct {
	active bool
	cgo    interface{} // CGO 实现或 nil
	stats  map[string]interface{}
}

// NewZ3Solver 创建新的 Z3 求解器（存根版本）
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

	// 使用存根实现
	fmt.Printf("Z3 CGO not available, using stub implementation\n")
	impl.active = false
	impl.stats["version"] = "Z3 Stub Implementation"
	impl.stats["available"] = false
	impl.stats["message"] = "Z3 CGO not compiled in"

	return impl, nil
}

// CheckPathFeasibility 检查路径可行性
func (z *Z3SolverImpl) CheckPathFeasible(from, to interface{}) bool {
	// 使用存根实现
	return z.checkPathFeasibilityStub(from, to)
}

// CheckOverflow 检查整数溢出
func (z *Z3SolverImpl) CheckOverflow(lhs, rhs interface{}) bool {
	// 使用存根实现
	return z.checkOverflowStub(lhs, rhs)
}

// CheckUnderflow 检查整数下溢（无符号减法回绕）
func (z *Z3SolverImpl) CheckUnderflow(lhs, rhs interface{}) bool {
	// 使用存根实现
	return z.checkUnderflowStub(lhs, rhs)
}

// Close 清理资源
func (z *Z3SolverImpl) Close() {
	z.active = false
}

// String 返回求解器的字符串表示
func (z *Z3SolverImpl) String() string {
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

// 以下是存根实现的方法

func (z *Z3SolverImpl) checkPathFeasibilityStub(from, to interface{}) bool {
	// 简化的存根实现
	return true
}

func (z *Z3SolverImpl) checkOverflowStub(lhs, rhs interface{}) bool {
	// 基本的整数溢出检查
	// 尝试提取字面量值
	lhsVal, lhsOk := z.extractIntValue(lhs)
	rhsVal, rhsOk := z.extractIntValue(rhs)

	if lhsOk && rhsOk {
		// 两个字面量，可以检查
		product := lhsVal * rhsVal
		// 检查是否超出 32 位整数范围
		return product > 0x7fffffff || product < -0x80000000
	}

	// 对于复杂表达式，保守处理
	return false
}

func (z *Z3SolverImpl) checkUnderflowStub(lhs, rhs interface{}) bool {
	// 基本的整数下溢检查
	// 尝试提取字面量值
	lhsVal, lhsOk := z.extractIntValue(lhs)
	rhsVal, rhsOk := z.extractIntValue(rhs)

	if lhsOk && rhsOk {
		// 对于无符号减法，如果 rhs > lhs 则会下溢
		// 这里我们检查是否可能发生下溢
		return rhsVal > lhsVal
	}

	// 对于复杂表达式，保守处理
	return false
}

func (z *Z3SolverImpl) extractIntValue(v interface{}) (int64, bool) {
	switch val := v.(type) {
	case int:
		return int64(val), true
	case int32:
		return int64(val), true
	case int64:
		return val, true
	case string:
		if i, err := strconv.ParseInt(val, 0, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}
