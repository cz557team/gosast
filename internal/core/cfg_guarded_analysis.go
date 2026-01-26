package core

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// CFGGuardedAnalysis 基于CFG的守卫调用分析
// 识别并追踪守卫调用初始化的变量在CFG中的影响
type CFGGuardedAnalysis struct {
	cfg         *CFG
	ctx         *AnalysisContext
	guardedVars map[string]map[int]bool  // 变量名 -> CFG节点ID集合（在这些节点之后，变量已初始化）
}

// NewCFGGuardedAnalysis 创建基于CFG的守卫调用分析
func NewCFGGuardedAnalysis(cfg *CFG, ctx *AnalysisContext) *CFGGuardedAnalysis {
	return &CFGGuardedAnalysis{
		cfg:         cfg,
		ctx:         ctx,
		guardedVars: make(map[string]map[int]bool),
	}
}

// Analyze 执行分析
func (cga *CFGGuardedAnalysis) Analyze() error {
	if cga.cfg == nil {
		return nil
	}

	// 遍历所有CFG节点
	for _, node := range cga.cfg.Nodes {
		cga.analyzeCFGNode(node)
	}

	return nil
}

// analyzeCFGNode 分析CFG节点
func (cga *CFGGuardedAnalysis) analyzeCFGNode(node *CFGNode) {
	// 检查节点中的所有语句
	for _, stmt := range node.Statements {
		cga.analyzeStatementInCFG(stmt, node)
	}
}

// analyzeStatementInCFG 在CFG上下文中分析语句
func (cga *CFGGuardedAnalysis) analyzeStatementInCFG(stmt *sitter.Node, currentNode *CFGNode) {
	if stmt == nil {
		return
	}

	stmtType := stmt.Type()

	// if语句：检查守卫调用模式
	if stmtType == "if_statement" {
		cga.analyzeGuardedIf(stmt, currentNode)
	}

	// 递归分析子语句
	for i := 0; i < int(stmt.ChildCount()); i++ {
		child := stmt.Child(i)
		if child != nil {
			cga.analyzeStatementInCFG(child, currentNode)
		}
	}
}

// analyzeGuardedIf 分析守卫if语句
func (cga *CFGGuardedAnalysis) analyzeGuardedIf(ifStmt *sitter.Node, currentNode *CFGNode) {
	// 获取条件
	condition := ifStmt.Child(0)
	if condition == nil {
		return
	}

	// 提取调用表达式
	callExpr := cga.extractCallExpressionRecursive(condition)
	if callExpr == nil {
		return
	}

	// 检查if体是否包含return
	consequence := ifStmt.Child(1)
	if consequence == nil {
		return
	}

	if !cga.containsReturnRecursive(consequence) {
		return
	}

	// 这是守卫调用模式：提取被初始化的变量
	cga.extractGuardedVariables(callExpr, ifStmt, currentNode)
}

// extractCallExpressionRecursive 递归提取调用表达式
func (cga *CFGGuardedAnalysis) extractCallExpressionRecursive(node *sitter.Node) *sitter.Node {
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
			if result := cga.extractCallExpressionRecursive(child); result != nil {
				return result
			}
		}
	}

	return nil
}

// containsReturnRecursive 递归检查是否包含return
func (cga *CFGGuardedAnalysis) containsReturnRecursive(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	if node.Type() == "return_statement" {
		return true
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && cga.containsReturnRecursive(child) {
			return true
		}
	}

	return false
}

// extractGuardedVariables 提取守卫变量并标记受影响的CFG节点
func (cga *CFGGuardedAnalysis) extractGuardedVariables(callExpr *sitter.Node, ifStmt *sitter.Node, currentNode *CFGNode) {
	if callExpr == nil || currentNode == nil {
		return
	}

	// 检查所有参数
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
					varName := cga.ctx.GetSourceText(operand)

					// 标记这个变量在守卫调用后的所有节点中都是已初始化的
					if cga.guardedVars[varName] == nil {
						cga.guardedVars[varName] = make(map[int]bool)
					}

					// 找到if语句之后的所有可达节点
					guardedNodes := cga.findReachableNodesAfter(ifStmt, currentNode)
					for _, nodeID := range guardedNodes {
						cga.guardedVars[varName][nodeID] = true
					}
				}
			}
		}
	}
}

// findReachableNodesAfter 查找if语句之后的可达CFG节点
func (cga *CFGGuardedAnalysis) findReachableNodesAfter(ifStmt *sitter.Node, currentNode *CFGNode) []int {
	if cga.cfg == nil {
		return nil
	}

	ifStmtLine := int(ifStmt.EndPoint().Row)

	// 收集在if语句之后的可达节点
	result := make([]int, 0)
	visited := make(map[int]bool)

	// 从当前节点的后继开始
	queue := make([]*CFGNode, 0)
	for _, succ := range currentNode.Successors {
		queue = append(queue, succ)
	}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		if visited[node.ID] {
			continue
		}
		visited[node.ID] = true

		// 检查节点中的第一条语句是否在if语句之后
		if len(node.Statements) > 0 {
			firstStmtLine := int(node.Statements[0].StartPoint().Row)
			if firstStmtLine > ifStmtLine {
				result = append(result, node.ID)
			}
		} else {
			// 空节点也加入
			result = append(result, node.ID)
		}

		// 添加后继
		for _, succ := range node.Successors {
			if !visited[succ.ID] {
				queue = append(queue, succ)
			}
		}
	}

	return result
}

// IsVariableGuardedAt 检查变量在指定节点是否被守卫
func (cga *CFGGuardedAnalysis) IsVariableGuardedAt(varName string, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 找到包含该节点的CFG基本块
	block := cga.findContainingBlock(node)
	if block == nil {
		return false
	}

	// 检查该变量是否在这个基本块中被守卫
	if guardedNodes, ok := cga.guardedVars[varName]; ok {
		if guardedNodes[block.ID] {
			return true
		}
	}

	return false
}

// findContainingBlock 查找包含AST节点的CFG基本块
func (cga *CFGGuardedAnalysis) findContainingBlock(node *sitter.Node) *CFGNode {
	if cga.cfg == nil {
		return nil
	}

	nodeStart := node.StartByte()
	nodeEnd := node.EndByte()

	for _, block := range cga.cfg.Nodes {
		for _, stmt := range block.Statements {
			stmtStart := stmt.StartByte()
			stmtEnd := stmt.EndByte()

			if nodeStart >= stmtStart && nodeEnd <= stmtEnd {
				return block
			}
		}
	}

	return nil
}
