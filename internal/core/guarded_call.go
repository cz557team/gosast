package core

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// GuardedCallAnalysis 守卫调用分析
// 识别模式: if (!func(&var)) { return; } use(var);
// 如果函数调用失败时会return，则后续代码可以假设变量已初始化
type GuardedCallAnalysis struct {
	ctx          *AnalysisContext
	guardedVars  map[string]*sitter.Node  // 变量 -> 守卫调用节点
	guardedRanges map[string][2]int       // 变量 -> [起始行, 结束行]
}

// NewGuardedCallAnalysis 创建守卫调用分析
func NewGuardedCallAnalysis(ctx *AnalysisContext) *GuardedCallAnalysis {
	return &GuardedCallAnalysis{
		ctx:          ctx,
		guardedVars:  make(map[string]*sitter.Node),
		guardedRanges: make(map[string][2]int),
	}
}

// Analyze 分析函数中的所有守卫调用
func (gca *GuardedCallAnalysis) Analyze(funcNode *sitter.Node) error {
	if funcNode == nil {
		return nil
	}

	// 查找函数体
	body := gca.findFunctionBody(funcNode)
	if body == nil {
		return nil
	}

	// 递归分析函数体
	gca.analyzeStatement(body)

	return nil
}

// analyzeStatement 分析语句
func (gca *GuardedCallAnalysis) analyzeStatement(stmt *sitter.Node) {
	if stmt == nil {
		return
	}

	stmtType := stmt.Type()

	// if语句：检查守卫调用模式
	if stmtType == "if_statement" {
		gca.analyzeIfStatement(stmt)
	}

	// 递归分析子语句
	for i := 0; i < int(stmt.ChildCount()); i++ {
		child := stmt.Child(i)
		if child != nil {
			gca.analyzeStatement(child)
		}
	}
}

// analyzeIfStatement 分析if语句
func (gca *GuardedCallAnalysis) analyzeIfStatement(ifStmt *sitter.Node) {
	// 获取条件
	condition := ifStmt.Child(0)
	if condition == nil {
		return
	}

	// 检查条件是否是函数调用（可能被!运算符取反）
	callExpr := gca.extractCallExpression(condition)
	if callExpr == nil {
		return
	}

	// 检查if体是否包含return（守卫模式）
	consequence := ifStmt.Child(1)
	if consequence == nil {
		return
	}

	if gca.containsReturn(consequence) {
		// 这是一个守卫调用模式
		// 提取被初始化的变量
		gca.extractInitializedVars(callExpr, ifStmt)
	}
}

// extractCallExpression 从条件中提取调用表达式
func (gca *GuardedCallAnalysis) extractCallExpression(condition *sitter.Node) *sitter.Node {
	if condition == nil {
		return nil
	}

	conditionType := condition.Type()

	// 直接的call_expression
	if conditionType == "call_expression" {
		return condition
	}

	// !运算符取反的调用
	// Tree-sitter可能将 !解析为 unary_expression 或 binary_expression
	if conditionType == "unary_expression" {
		// unary_expression 的结构: [operator, operand]
		for i := 0; i < int(condition.ChildCount()); i++ {
			child := condition.Child(i)
			if child != nil && child.Type() == "call_expression" {
				return child
			}
		}
	}

	// 括号表达式
	if conditionType == "parenthesized_expression" {
		inner := condition.Child(1)
		if inner != nil {
			return gca.extractCallExpression(inner)
		}
	}

	// 递归搜索所有子节点
	for i := 0; i < int(condition.ChildCount()); i++ {
		child := condition.Child(i)
		if child != nil {
			if result := gca.extractCallExpression(child); result != nil {
				return result
			}
		}
	}

	return nil
}

// containsReturn 检查语句是否包含return
func (gca *GuardedCallAnalysis) containsReturn(stmt *sitter.Node) bool {
	if stmt == nil {
		return false
	}

	// 直接的return语句
	if stmt.Type() == "return_statement" {
		return true
	}

	// 复合语句：检查子语句
	if stmt.Type() == "compound_statement" {
		for i := 0; i < int(stmt.ChildCount()); i++ {
			child := stmt.Child(i)
			if child != nil && gca.containsReturn(child) {
				return true
			}
		}
	}

	return false
}

// extractInitializedVars 提取守卫调用中初始化的变量
func (gca *GuardedCallAnalysis) extractInitializedVars(callExpr *sitter.Node, ifStmt *sitter.Node) {
	if callExpr == nil {
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
					varName := gca.ctx.GetSourceText(operand)

					// 这是一个守卫变量
					gca.guardedVars[varName] = callExpr

					// 计算有效范围：从if语句之后到函数结束
					ifStmtEnd := int(ifStmt.EndPoint().Row) + 1
					funcEnd := gca.findFunctionEnd(ifStmt)

					gca.guardedRanges[varName] = [2]int{ifStmtEnd, funcEnd}
				}
			}
		}
	}
}

// findFunctionEnd 查找函数结束行
func (gca *GuardedCallAnalysis) findFunctionEnd(node *sitter.Node) int {
	current := node.Parent()
	maxDepth := 50
	depth := 0

	for current != nil && depth < maxDepth {
		if current.Type() == "function_definition" {
			return int(current.EndPoint().Row) + 1
		}
		current = current.Parent()
		depth++
	}

	// 默认：返回当前行+100
	return int(node.EndPoint().Row) + 100
}

// findFunctionBody 查找函数体
func (gca *GuardedCallAnalysis) findFunctionBody(funcNode *sitter.Node) *sitter.Node {
	for i := 0; i < int(funcNode.ChildCount()); i++ {
		child := funcNode.Child(i)
		if child != nil && child.Type() == "compound_statement" {
			return child
		}
	}
	return nil
}

// IsGuardedVariable 检查变量是否是守卫变量（在守卫调用中初始化）
func (gca *GuardedCallAnalysis) IsGuardedVariable(varName string, useNode *sitter.Node) bool {
	if useNode == nil {
		return false
	}

	callNode, ok := gca.guardedVars[varName]
	if !ok {
		return false
	}

	// 检查使用点是否在有效范围内
	useLine := int(useNode.StartPoint().Row) + 1
	rng, ok := gca.guardedRanges[varName]
	if !ok {
		return false
	}

	if useLine < rng[0] || useLine > rng[1] {
		return false
	}

	// 检查使用点是否在守卫调用之后
	callLine := int(callNode.StartPoint().Row) + 1
	if useLine <= callLine {
		return false
	}

	return true
}

// GetGuardedCall 获取变量的守卫调用节点
func (gca *GuardedCallAnalysis) GetGuardedCall(varName string) *sitter.Node {
	return gca.guardedVars[varName]
}
