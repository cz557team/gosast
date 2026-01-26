package core

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// PathFeasibilityAnalyzer 路径可行性分析器
// 使用Z3验证某些代码路径是否实际可达
type PathFeasibilityAnalyzer struct {
	ctx    *AnalysisContext
	z3     *Z3Solver
	cfg    *CFG
}

// NewPathFeasibilityAnalyzer 创建路径可行性分析器
func NewPathFeasibilityAnalyzer(cfg *CFG, ctx *AnalysisContext, z3 *Z3Solver) *PathFeasibilityAnalyzer {
	return &PathFeasibilityAnalyzer{
		ctx: ctx,
		z3:  z3,
		cfg: cfg,
	}
}

// IsPathFeasible 检查从未初始化声明到使用点的路径是否可行
func (pfa *PathFeasibilityAnalyzer) IsPathFeasible(
	declNode *sitter.Node,
	useNode *sitter.Node,
	varName string,
) bool {
	if pfa.cfg == nil {
		return true // 没有CFG，假设路径可行（保守）
	}

	// 1. 找到包含声明和使用点的CFG节点
	declBlock := pfa.findNodeInCFG(declNode)
	useBlock := pfa.findNodeInCFG(useNode)

	if declBlock == nil || useBlock == nil {
		return true
	}

	// 2. 检查是否有路径从声明到使用点
	hasPath := pfa.hasPathBetween(declBlock, useBlock)
	if !hasPath {
		return false
	}

	// 3. 检查路径上的守卫调用
	if pfa.isGuardedOnAllPaths(declNode, useNode, varName) {
		return false // 所有路径都有守卫，不可达
	}

	// 4. 使用Z3验证路径可行性（如果可用）
	if pfa.z3 != nil {
		return pfa.verifyWithZ3(declNode, useNode, varName)
	}

	return true
}

// findNodeInCFG 在CFG中查找包含AST节点的块
func (pfa *PathFeasibilityAnalyzer) findNodeInCFG(node *sitter.Node) *CFGNode {
	if pfa.cfg == nil || node == nil {
		return nil
	}

	nodeStart := node.StartByte()
	nodeEnd := node.EndByte()

	for _, block := range pfa.cfg.Nodes {
		for _, stmt := range block.Statements {
			stmtStart := stmt.StartByte()
			stmtEnd := stmt.EndByte()

			// 检查节点是否在语句范围内
			if nodeStart >= stmtStart && nodeEnd <= stmtEnd {
				return block
			}
		}
	}

	return nil
}

// hasPathBetween 检查两个CFG块之间是否有路径
func (pfa *PathFeasibilityAnalyzer) hasPathBetween(from, to *CFGNode) bool {
	if from == nil || to == nil {
		return false
	}

	// 如果是同一个块
	if from.ID == to.ID {
		return true
	}

	// BFS搜索路径
	visited := make(map[int]bool)
	queue := []*CFGNode{from}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.ID] {
			continue
		}
		visited[current.ID] = true

		// 找到目标
		if current.ID == to.ID {
			return true
		}

		// 添加后继
		for _, succ := range current.Successors {
			if !visited[succ.ID] {
				queue = append(queue, succ)
			}
		}
	}

	return false
}

// isGuardedOnAllPaths 检查所有路径上是否有守卫调用
func (pfa *PathFeasibilityAnalyzer) isGuardedOnAllPaths(
	declNode *sitter.Node,
	useNode *sitter.Node,
	varName string,
) bool {
	// 查找声明和使用之间的所有if语句
	ifStmts := pfa.findIfStatementsBetween(declNode, useNode)

	// 检查这些if语句是否是守卫调用
	for _, ifStmt := range ifStmts {
		if pfa.isGuardedCallForVar(ifStmt, varName) {
			// 找到一个守卫调用
			// 检查使用点是否在守卫之后
			useLine := int(useNode.StartPoint().Row)
			ifStmtLine := int(ifStmt.EndPoint().Row)

			if useLine > ifStmtLine {
				return true
			}
		}
	}

	return false
}

// findIfStatementsBetween 查找两个节点之间的所有if语句
func (pfa *PathFeasibilityAnalyzer) findIfStatementsBetween(from, to *sitter.Node) []*sitter.Node {
	result := make([]*sitter.Node, 0)

	fromLine := int(from.StartPoint().Row)
	toLine := int(to.StartPoint().Row)

	// 向上查找共同的父节点
	ancestor := pfa.findCommonAncestor(from, to)
	if ancestor == nil {
		return result
	}

	// 遍历祖先的子节点
	pfa.collectIfStatementsInRange(ancestor, fromLine, toLine, &result)

	return result
}

// findCommonAncestor 查找共同祖先
func (pfa *PathFeasibilityAnalyzer) findCommonAncestor(node1, node2 *sitter.Node) *sitter.Node {
	if node1 == nil || node2 == nil {
		return nil
	}

	// 收集node1的所有祖先
	ancestors1 := make(map[*sitter.Node]bool)
	current := node1.Parent()
	for current != nil {
		ancestors1[current] = true
		current = current.Parent()
	}

	// 找到node2的第一个在ancestors1中的祖先
	current = node2.Parent()
	for current != nil {
		if ancestors1[current] {
			return current
		}
		current = current.Parent()
	}

	return nil
}

// collectIfStatementsInRange 收集范围内的所有if语句
func (pfa *PathFeasibilityAnalyzer) collectIfStatementsInRange(
	node *sitter.Node,
	fromLine, toLine int,
	result *[]*sitter.Node,
) {
	if node == nil {
		return
	}

	nodeType := node.Type()

	// 如果是if语句，检查是否在范围内
	if nodeType == "if_statement" {
		nodeLine := int(node.StartPoint().Row)
		if nodeLine >= fromLine && nodeLine <= toLine {
			*result = append(*result, node)
		}
	}

	// 递归搜索子节点
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			pfa.collectIfStatementsInRange(child, fromLine, toLine, result)
		}
	}
}

// isGuardedCallForVar 检查if语句是否是对特定变量的守卫调用
func (pfa *PathFeasibilityAnalyzer) isGuardedCallForVar(ifStmt *sitter.Node, varName string) bool {
	// 获取条件
	condition := ifStmt.Child(0)
	if condition == nil {
		return false
	}

	// 提取调用表达式
	callExpr := pfa.extractCallExpressionRecursive(condition)
	if callExpr == nil {
		return false
	}

	// 检查if体是否包含return
	consequence := ifStmt.Child(1)
	if consequence == nil {
		return false
	}

	if !pfa.containsReturnRecursive(consequence) {
		return false
	}

	// 检查调用参数中是否包含 &varName
	for i := 1; i < int(callExpr.ChildCount()); i++ {
		arg := callExpr.Child(i)
		if arg == nil || arg.Type() != "argument" {
			continue
		}

		if arg.ChildCount() > 0 {
			expr := arg.Child(0)
			if expr != nil && expr.Type() == "address_of_expression" {
				operand := expr.Child(0)
				if operand != nil && operand.Type() == "identifier" {
					argVarName := pfa.ctx.GetSourceText(operand)
					if argVarName == varName {
						return true // 找到了！
					}
				}
			}
		}
	}

	return false
}

// extractCallExpressionRecursive 递归提取调用表达式
func (pfa *PathFeasibilityAnalyzer) extractCallExpressionRecursive(node *sitter.Node) *sitter.Node {
	if node == nil {
		return nil
	}

	if node.Type() == "call_expression" {
		return node
	}

	// 递归搜索
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			if result := pfa.extractCallExpressionRecursive(child); result != nil {
				return result
			}
		}
	}

	return nil
}

// containsReturnRecursive 递归检查是否包含return
func (pfa *PathFeasibilityAnalyzer) containsReturnRecursive(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	if node.Type() == "return_statement" {
		return true
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && pfa.containsReturnRecursive(child) {
			return true
		}
	}

	return false
}

// verifyWithZ3 使用Z3验证路径可行性
func (pfa *PathFeasibilityAnalyzer) verifyWithZ3(
	declNode *sitter.Node,
	useNode *sitter.Node,
	varName string,
) bool {
	if pfa.z3 == nil {
		return true // 没有Z3，假设可行
	}

	// 构建约束：变量必须已初始化
	// 这是一个简化版本，实际需要更复杂的路径条件建模

	// TODO: 完整的Z3路径验证需要：
	// 1. 提取路径条件
	// 2. 建立符号变量
	// 3. 添加约束
	// 4. 求解

	// 暂时返回true（保守策略）
	return true
}

// IsUnreachablePath 检查路径是否不可达
// 这是对外的主要接口
func (pfa *PathFeasibilityAnalyzer) IsUnreachablePath(
	useNode *sitter.Node,
	varName string,
) bool {
	// 查找变量声明
	declNode := pfa.findVariableDeclaration(varName, useNode)
	if declNode == nil {
		return false
	}

	// 检查路径可行性
	return !pfa.IsPathFeasible(declNode, useNode, varName)
}

// findVariableDeclaration 查找变量声明
func (pfa *PathFeasibilityAnalyzer) findVariableDeclaration(varName string, useNode *sitter.Node) *sitter.Node {
	if useNode == nil {
		return nil
	}

	// 向上搜索，找到变量声明
	current := useNode.Parent()
	maxDepth := 100
	depth := 0

	for current != nil && depth < maxDepth {
		// 检查当前节点是否包含变量声明
		if pfa.containsVariableDeclaration(current, varName) {
			return current
		}

		current = current.Parent()
		depth++
	}

	return nil
}

// containsVariableDeclaration 检查节点是否包含变量声明
func (pfa *PathFeasibilityAnalyzer) containsVariableDeclaration(node *sitter.Node, varName string) bool {
	if node == nil {
		return false
	}

	nodeType := node.Type()

	// 检查是否是声明
	if nodeType == "declaration" {
		// 提取声明的变量名
		declaredVar := pfa.extractDeclaredVariableName(node)
		return declaredVar == varName
	}

	// 检查子节点
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && pfa.containsVariableDeclaration(child, varName) {
			return true
		}
	}

	return false
}

// extractDeclaredVariableName 提取声明的变量名
func (pfa *PathFeasibilityAnalyzer) extractDeclaredVariableName(decl *sitter.Node) string {
	if decl == nil {
		return ""
	}

	for i := 0; i < int(decl.ChildCount()); i++ {
		child := decl.Child(i)
		if child == nil {
			continue
		}

		childType := child.Type()

		// 直接的identifier（简单声明）
		if childType == "identifier" && i > 0 {
			return pfa.ctx.GetSourceText(child)
		}

		// init_declarator
		if childType == "init_declarator" && child.ChildCount() > 0 {
			firstChild := child.Child(0)
			if firstChild.Type() == "identifier" {
				return pfa.ctx.GetSourceText(firstChild)
			}
		}
	}

	return ""
}
