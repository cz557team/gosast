package core

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ProtectionPattern 保护模式类型
type ProtectionPattern string

const (
	PatternGuardReturn   ProtectionPattern = "guard_return"
	PatternNonNullCheck  ProtectionPattern = "non_null_check"
	PatternIfBlock       ProtectionPattern = "if_block"
	PatternBreak         ProtectionPattern = "break"
	PatternContinue      ProtectionPattern = "continue"
)

// ProtectionState 保护状态
type ProtectionState struct {
	Line              int
	ProtectedPointers map[string]bool
	Patterns          map[ProtectionPattern]bool
}

// ProtectionFramework 统一保护框架
type ProtectionFramework struct {
	lineStates map[int]*ProtectionState
}

// NewProtectionFramework 创建新的保护框架
func NewProtectionFramework() *ProtectionFramework {
	return &ProtectionFramework{
		lineStates: make(map[int]*ProtectionState),
	}
}

// Reset 重置框架状态
func (pf *ProtectionFramework) Reset() {
	pf.lineStates = make(map[int]*ProtectionState)
}

// AddProtectionPattern 添加保护模式
func (pf *ProtectionFramework) AddProtectionPattern(line int, pattern ProtectionPattern, pointers []string) {
	if pf.lineStates[line] == nil {
		pf.lineStates[line] = &ProtectionState{
			Line:              line,
			ProtectedPointers: make(map[string]bool),
			Patterns:          make(map[ProtectionPattern]bool),
		}
	}

	pf.lineStates[line].Patterns[pattern] = true
	for _, ptr := range pointers {
		pf.lineStates[line].ProtectedPointers[ptr] = true
	}
}

// IsProtected 检查指定行和变量是否受保护
func (pf *ProtectionFramework) IsProtected(line int, varName string) bool {
	// 检查当前行是否受保护
	if state, exists := pf.lineStates[line]; exists {
		// 如果有任何保护模式，则受保护
		if len(state.Patterns) > 0 {
			return true
		}
		// 如果变量在受保护列表中
		if state.ProtectedPointers[varName] {
			return true
		}
	}

	// 检查是否在守护性返回之后
	for l := line - 1; l >= 0; l-- {
		if state, exists := pf.lineStates[l]; exists {
			if state.Patterns[PatternGuardReturn] {
				return true
			}
			// 如果找到变量的保护检查，停止往前查找
			if state.ProtectedPointers[varName] {
				break
			}
		}
	}

	return false
}

// AnalyzeGuardReturnPatterns 分析守护性返回模式
func (pf *ProtectionFramework) AnalyzeGuardReturnPatterns(ctx *AnalysisContext, funcNode *sitter.Node) {
	pf.findAndMarkGuardReturns(ctx, funcNode, 0)
}

// findAndMarkGuardReturns 查找并标记守护性返回
func (pf *ProtectionFramework) findAndMarkGuardReturns(ctx *AnalysisContext, node *sitter.Node, currentLine int) {
	if node.Type() == "if_statement" {
		pf.processIfForGuardReturn(ctx, node)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		pf.findAndMarkGuardReturns(ctx, child, currentLine)
	}
}

// processIfForGuardReturn 处理if语句中的守护性返回
func (pf *ProtectionFramework) processIfForGuardReturn(ctx *AnalysisContext, ifNode *sitter.Node) {
	condition := ifNode.ChildByFieldName("condition")
	if condition == nil {
		return
	}

	// 获取if块
	ifBlock := ifNode.Child(2)
	if ifBlock == nil {
		return
	}

	// 检查if块内是否有终止语句
	if pf.hasTerminatingStatement(ctx, ifBlock) {
		// 标记后续行为安全
		ifEndLine := int(ifNode.EndPoint().Row)
		blockEndLine := int(ifBlock.EndPoint().Row)

		for line := ifEndLine; line <= blockEndLine; line++ {
			pf.AddProtectionPattern(line, PatternGuardReturn, nil)
		}
	}

	// 处理非NULL检查
	if pf.isNonNullCheck(ctx, condition) {
		// 标记if块内的行为安全
		startLine := int(ifBlock.StartPoint().Row)
		endLine := int(ifBlock.EndPoint().Row)

		for line := startLine; line <= endLine; line++ {
			pf.AddProtectionPattern(line, PatternIfBlock, nil)
		}

		// 提取检查的变量名
		checkedVar := pf.extractCheckedVariable(ctx, condition)
		if checkedVar != "" {
			for line := startLine; line <= endLine; line++ {
				pf.AddProtectionPattern(line, PatternNonNullCheck, []string{checkedVar})
			}
		}
	}

	// 处理else块
	elseClause := ifNode.ChildByFieldName("else")
	if elseClause != nil {
		pf.findAndMarkGuardReturns(ctx, elseClause, int(elseClause.StartPoint().Row))
	}
}

// hasTerminatingStatement 检查块内是否有终止语句
func (pf *ProtectionFramework) hasTerminatingStatement(ctx *AnalysisContext, node *sitter.Node) bool {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if pf.isTerminatingNode(child) {
			return true
		}
		if pf.hasTerminatingStatement(ctx, child) {
			return true
		}
	}
	return false
}

// isTerminatingNode 检查是否为终止节点
func (pf *ProtectionFramework) isTerminatingNode(node *sitter.Node) bool {
	nodeType := node.Type()
	return nodeType == "return_statement" ||
		nodeType == "break_statement" ||
		nodeType == "continue_statement" ||
		nodeType == "goto_statement" ||
		nodeType == "throw_statement"
}

// isNonNullCheck 检查是否为非NULL检查
func (pf *ProtectionFramework) isNonNullCheck(ctx *AnalysisContext, condition *sitter.Node) bool {
	condText := strings.TrimSpace(ctx.GetSourceText(condition))
	return strings.Contains(condText, "!=") && strings.Contains(condText, "NULL")
}

// extractCheckedVariable 提取检查的变量名
func (pf *ProtectionFramework) extractCheckedVariable(ctx *AnalysisContext, condition *sitter.Node) string {
	condText := strings.TrimSpace(ctx.GetSourceText(condition))

	// 简单的变量名提取（可以进一步改进）
	// 查找 != NULL 之前的标识符
	if idx := strings.Index(condText, "!="); idx > 0 {
		varName := strings.TrimSpace(condText[:idx])
		// 移除可能的指针操作符
		if strings.Contains(varName, "*") {
			varName = strings.TrimSpace(strings.Split(varName, "*")[0])
		}
		return varName
	}

	return ""
}
