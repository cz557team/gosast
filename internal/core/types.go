package core

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// TaintEngine 污点分析引擎接口
type TaintEngine interface {
	// 注册污点源
	AddSource(nodeType string, handler SourceHandler)
	// 注册传播规则
	AddPropagator(nodeType string, handler PropagatorHandler)
	// IsTainted 检查节点是否被污染
	IsTainted(node *sitter.Node) bool
	// GetTaintPath 获取污染路径
	GetTaintPath(node *sitter.Node) []TaintStep
	// 执行污点传播分析
	Propagate(cfg *CFG) error
	// 重置污点状态
	Reset()
	// 获取统计信息
	GetStats() map[string]interface{}
	// markTainted 标记节点为污染（内部使用）
	markTainted(node *sitter.Node)
}

// SourceHandler 污点源处理器
type SourceHandler func(node *sitter.Node, ctx *AnalysisContext) bool

// PropagatorHandler 传播规则处理器
type PropagatorHandler func(node *sitter.Node, ctx *AnalysisContext, engine *MemoryTaintEngine) []TaintStep

// TaintStep 表示污点传播的一步
type TaintStep struct {
	From   *sitter.Node
	To     *sitter.Node
	Reason string
}

// Z3Solver Z3 约束求解器接口
type Z3Solver interface {
	// CheckPathFeasible 检查路径是否可行
	CheckPathFeasible(from, to interface{}) bool
	// CheckOverflow 检查是否存在整数溢出
	CheckOverflow(lhs, rhs interface{}) bool
	// CheckUnderflow 检查是否存在整数下溢（无符号减法回绕）
	CheckUnderflow(lhs, rhs interface{}) bool
	// Close 清理资源
	Close()
	// GetSolverStats 获取求解器统计信息
	GetSolverStats() map[string]interface{}
	// String 返回求解器的字符串表示
	String() string
	// IsAvailable 检查求解器是否可用
	IsAvailable() bool
}