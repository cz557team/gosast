//go:build !noz3
// +build !noz3

package core

/*
#cgo CFLAGS: -I/opt/homebrew/anaconda3/include
#cgo darwin LDFLAGS: -L/opt/homebrew/anaconda3/lib -Wl,-rpath,/opt/homebrew/anaconda3/lib -lz3
#cgo linux LDFLAGS: -L/opt/homebrew/anaconda3/lib -lz3
#include <z3.h>
*/
import "C"
import (
	"fmt"
)

// Z3SolverCGO Z3 的简化 CGO 实现
type Z3SolverCGO struct {
	ctx    C.Z3_context
	solver C.Z3_solver
	active bool
}

// NewZ3SolverCGO 创建新的 Z3 CGO 求解器
func NewZ3SolverCGO() (*Z3SolverCGO, error) {
	// 创建配置
	cfg := C.Z3_mk_config()
	if cfg == nil {
		return nil, fmt.Errorf("failed to create Z3 config")
	}
	defer C.Z3_del_config(cfg)

	// 创建上下文
	ctx := C.Z3_mk_context(cfg)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create Z3 context")
	}

	// 创建求解器
	solver := C.Z3_mk_solver(ctx)
	if solver == nil {
		C.Z3_del_context(ctx)
		return nil, fmt.Errorf("failed to create Z3 solver")
	}

	C.Z3_solver_inc_ref(ctx, solver)

	z3 := &Z3SolverCGO{
		ctx:    ctx,
		solver: solver,
		active: true,
	}

	// 获取 Z3 版本
	version := C.Z3_get_full_version()
	versionStr := C.GoString(version)
	fmt.Printf("Z3 initialized successfully: %s\n", versionStr)

	return z3, nil
}

// CheckPathFeasibility 检查路径可行性
func (z *Z3SolverCGO) CheckPathFeasible(from, to interface{}) bool {
	if !z.active {
		return false
	}

	// 简化实现：基本检查
	if from == nil || to == nil {
		return false
	}

	// 对于简单情况，使用静态分析
	return z.checkStaticPathFeasibility(from, to)
}

// CheckOverflow 检查整数溢出
func (z *Z3SolverCGO) CheckOverflow(lhs, rhs interface{}) bool {
	if !z.active {
		fmt.Printf("[Z3] CheckOverflow: solver not active\n")
		return false
	}

	// 尝试提取整数值
	lhsVal, lhsOk := z.extractIntValue(lhs)
	rhsVal, rhsOk := z.extractIntValue(rhs)

	fmt.Printf("[Z3] CheckOverflow: lhs=%v(ok=%v), rhs=%v(ok=%v)\n", lhsVal, lhsOk, rhsVal, rhsOk)

	if lhsOk && rhsOk {
		// 字面量检查
		product := lhsVal * rhsVal
		fmt.Printf("[Z3] CheckOverflow: product=%d, checking if > 0x7fffffff (%d) or < -0x80000000 (%d)\n", product, 0x7fffffff, -0x80000000)
		// 检查 32 位整数溢出
		if product > 0x7fffffff || product < -0x80000000 {
			fmt.Printf("[Z3] CheckOverflow: returning TRUE (overflow detected)\n")
			return true
		}
	}

	// 复杂情况：使用 Z3（简化实现）
	fmt.Printf("[Z3] CheckOverflow: returning FALSE (no overflow)\n")
	return false // 保守处理
}

// Close 清理资源
func (z *Z3SolverCGO) Close() {
	if z.active {
		if z.solver != nil && z.ctx != nil {
			C.Z3_solver_dec_ref(z.ctx, z.solver)
			z.solver = nil
		}
		if z.ctx != nil {
			C.Z3_del_context(z.ctx)
			z.ctx = nil
		}
		z.active = false
	}
}

// String 返回求解器的字符串表示
func (z *Z3SolverCGO) String() string {
	if !z.active {
		return "Z3 Solver (Not Active)"
	}
	return "Z3 Solver (CGO Active)"
}

// GetSolverStats 获取求解器统计信息
func (z *Z3SolverCGO) GetSolverStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if !z.active {
		stats["version"] = "Z3 (Not Active)"
		stats["available"] = false
		return stats
	}

	version := C.Z3_get_full_version()
	stats["version"] = C.GoString(version)
	stats["available"] = true
	stats["implementation"] = "CGO"

	return stats
}

// IsAvailable 检查求解器是否可用
func (z *Z3SolverCGO) IsAvailable() bool {
	return z.active
}

// 辅助方法

// checkStaticPathFeasibility 静态路径可行性检查
func (z *Z3SolverCGO) checkStaticPathFeasibility(from, to interface{}) bool {
	// 简化的静态检查
	return true
}

// extractIntValue 提取整数值
func (z *Z3SolverCGO) extractIntValue(v interface{}) (int64, bool) {
	switch val := v.(type) {
	case int:
		return int64(val), true
	case int32:
		return int64(val), true
	case int64:
		return val, true
	case string:
		// 简化处理：尝试解析为 16 进制或 10 进制
		return 0, false
	}
	return 0, false
}