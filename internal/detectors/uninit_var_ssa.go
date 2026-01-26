package detectors

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// UninitVarSSADetector 基于 SSA + 到达定义的未初始化变量检测器 (2024-2025)
// 实现：CGO 2024 SSA 形式 + 到达定义分析 + 保守的可利用性检查
type UninitVarSSADetector struct {
	*core.BaseDetector
}

// NewUninitVarSSADetector 创建新的未初始化变量检测器
func NewUninitVarSSADetector() *UninitVarSSADetector {
	return &UninitVarSSADetector{
		BaseDetector: core.NewBaseDetector(
			"uninit_var_ssa",
			"Detects uninitialized variables using SSA form and reaching definitions analysis (CGO 2024)",
		),
	}
}

// Name 返回检测器名称
func (d *UninitVarSSADetector) Name() string {
	return "Uninitialized Variable Detector"
}

// Description 返回检测器描述
func (d *UninitVarSSADetector) Description() string {
	return "Detects uninitialized variables using SSA form and reaching definitions analysis (CGO 2024)"
}

// Run 执行检测
func (d *UninitVarSSADetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 使用 Tree-sitter 查询查找所有函数定义
	query := `
		(function_definition
			body: (compound_statement) @body
		) @func
	`

	matches, err := ctx.Query(query)
	if err != nil {
		return nil, err
	}

	for _, match := range matches {
		bodyNode := match.Captures["body"]
		if bodyNode == nil {
			continue
		}

		// 分析函数体内的未初始化变量
		d.analyzeFunctionBody(ctx, bodyNode, &vulns)
	}

	return vulns, nil
}

// SSAState SSA 状态（到达定义分析）
type SSAState struct {
	// 变量定义位置: varName -> declaratorNode
	declarations map[string]*sitter.Node
	// 变量是否已初始化: varName -> initialized
	initialized map[string]bool
	// 未初始化变量集合（保守）
	uninitializedVars map[string]bool
	// 部分初始化的变量（如结构体成员赋值）
	partiallyInitialized map[string]bool
}

// analyzeFunctionBody 分析函数体内的未初始化变量使用
func (d *UninitVarSSADetector) analyzeFunctionBody(ctx *core.AnalysisContext, body *sitter.Node, vulns *[]core.DetectorVulnerability) {
	// 1. 构建 SSA 形式和到达定义
	state := d.buildSSA(ctx, body)

	// 2. 分析未初始化变量使用
	d.scanUninitializedUses(ctx, body, state, vulns)
}

// buildSSA 构建 SSA 形式（简化版，基于到达定义）
func (d *UninitVarSSADetector) buildSSA(ctx *core.AnalysisContext, body *sitter.Node) *SSAState {
	state := &SSAState{
		declarations:         make(map[string]*sitter.Node),
		initialized:          make(map[string]bool),
		uninitializedVars:    make(map[string]bool),
		partiallyInitialized: make(map[string]bool),
	}

	// 第一遍：收集所有声明
	d.collectDeclarations(ctx, body, state)

	// 第二遍：数据流分析，跟踪初始化状态
	d.performDataflowAnalysis(ctx, body, state)

	return state
}

// collectDeclarations 收集所有变量声明（非初始化声明）
func (d *UninitVarSSADetector) collectDeclarations(ctx *core.AnalysisContext, node *sitter.Node, state *SSAState) {
	if node == nil {
		return
	}

	nodeType := core.SafeType(node)
	if nodeType == "declaration" {
		d.processDeclaration(ctx, node, state)
	} else if nodeType == "for_statement" {
		d.processForLoopDeclaration(ctx, node, state)
	}

	// 递归处理子节点（但跳过嵌套函数定义）
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if core.SafeType(child) != "function_definition" {
			d.collectDeclarations(ctx, child, state)
		}
	}
}

// processDeclaration 处理声明语句
func (d *UninitVarSSADetector) processDeclaration(ctx *core.AnalysisContext, declNode *sitter.Node, state *SSAState) {
	// C 语言的声明有两种形式：
	// 1. int x;           -> declaration(primitive_type, identifier, ;)
	// 2. int x = 5;       -> declaration(primitive_type, init_declarator(identifier, =, 5), ;)
	// 3. int a, b, c;     -> declaration(primitive_type, identifier, ,, identifier, ,, identifier, ;)
	// 4. int arr[10];     -> declaration(primitive_type, array_declarator(identifier, [size]), ;)

	// 首先检查整个声明是否有 static 存储类
	hasStaticStorage := d.hasStaticStorageClass(declNode)

	// 检查子节点类型
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		childType := core.SafeType(child)

		if childType == "init_declarator" {
			// 带初始化器的声明符
			d.processInitDeclarator(ctx, child, state)
		} else if childType == "identifier" {
			// 简单声明符（没有初始化器）
			varName := ctx.GetSourceText(child)

			// 检查是否是静态存储变量（static、全局变量等）
			if hasStaticStorage || !d.isInsideFunction(child) {
				// 静态存储变量默认初始化为0
				state.initialized[varName] = true
				state.declarations[varName] = child
			} else {
				// 局部变量，未初始化
				state.uninitializedVars[varName] = true
				state.initialized[varName] = false
				state.declarations[varName] = child
			}
		} else if childType == "array_declarator" {
			// 数组声明符（如 int arr[10]）
			varName := d.extractDeclaratorName(ctx, child)
			if varName != "" {
				// 检查是否是静态存储变量
				if hasStaticStorage || !d.isInsideFunction(child) {
					// 静态存储变量默认初始化为0
					state.initialized[varName] = true
					state.declarations[varName] = child
				} else {
					// 局部变量，未初始化
					state.uninitializedVars[varName] = true
					state.initialized[varName] = false
					state.declarations[varName] = child
				}
			}
		}
	}

	// 处理逗号分隔的声明
	d.handleCommaSeparatedDecls(ctx, declNode, state, hasStaticStorage)
}

// handleCommaSeparatedDecls 处理逗号分隔的声明（如 int a, b, c;）
func (d *UninitVarSSADetector) handleCommaSeparatedDecls(ctx *core.AnalysisContext, declNode *sitter.Node, state *SSAState, hasStaticStorage bool) {
	// 查找逗号分隔的标识符
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if core.SafeType(child) == "," {
			// 找到下一个标识符
			for j := i + 1; j < int(core.SafeChildCount(declNode)); j++ {
				nextChild := core.SafeChild(declNode, j)
				nextType := core.SafeType(nextChild)

				if nextType == "identifier" {
					varName := ctx.GetSourceText(nextChild)
					// 检查是否是静态存储变量
					if hasStaticStorage || !d.isInsideFunction(nextChild) {
						// 静态存储变量默认初始化为0
						state.initialized[varName] = true
						state.declarations[varName] = nextChild
					} else {
						// 局部变量，未初始化
						state.uninitializedVars[varName] = true
						state.initialized[varName] = false
						state.declarations[varName] = nextChild
					}
					break
				} else if nextType == "," || nextType == ";" || nextType == "=" {
					continue
				} else {
					break
				}
			}
		}
	}
}

// isGlobal 检查是否是全局变量（不在函数定义内）
func (d *UninitVarSSADetector) isGlobal(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	parent := node.Parent()
	depth := 0
	maxDepth := 10

	for parent != nil && depth < maxDepth {
		if core.SafeType(parent) == "function_definition" {
			return false // 在函数内
		}
		parent = parent.Parent()
		depth++
	}

	return true // 没有找到函数定义父节点，可能是全局变量
}

// processInitDeclarator 处理初始化声明符
func (d *UninitVarSSADetector) processInitDeclarator(ctx *core.AnalysisContext, initDecl *sitter.Node, state *SSAState) {
	count := core.SafeChildCount(initDecl)
	if count < 1 {
		return
	}

	// 获取声明符（变量名）
	declarator := core.SafeChild(initDecl, 0)
	varName := d.extractDeclaratorName(ctx, declarator)

	if varName == "" {
		return
	}

	// 检查是否有初始化器 (=)
	hasInitializer := false
	for i := 1; i < int(count); i++ {
		child := core.SafeChild(initDecl, i)
		if core.SafeType(child) == "=" {
			hasInitializer = true
			break
		}
	}

	// 记录声明
	state.declarations[varName] = declarator

	// 记录初始化状态
	if hasInitializer {
		state.initialized[varName] = true
		delete(state.uninitializedVars, varName)
	} else {
		// 未初始化声明
		// 排除静态变量（默认为0）
		if !d.isStaticStorage(declarator) {
			state.uninitializedVars[varName] = true
			state.initialized[varName] = false
		} else {
			// 静态变量默认初始化为0
			state.initialized[varName] = true
		}
	}
}

// extractDeclaratorName 从声明符中提取变量名
func (d *UninitVarSSADetector) extractDeclaratorName(ctx *core.AnalysisContext, declarator *sitter.Node) string {
	if declarator == nil {
		return ""
	}

	declType := core.SafeType(declarator)

	// 直接是标识符
	if declType == "identifier" {
		return ctx.GetSourceText(declarator)
	}

	// 数组声明符：array_declarator -> declarator [size]
	if declType == "array_declarator" {
		if core.SafeChildCount(declarator) >= 1 {
			return d.extractDeclaratorName(ctx, core.SafeChild(declarator, 0))
		}
	}

	// 指针声明符：pointer_declarator -> * declarator
	if declType == "pointer_declarator" {
		if core.SafeChildCount(declarator) >= 2 {
			return d.extractDeclaratorName(ctx, core.SafeChild(declarator, 1))
		}
	}

	// 函数声明符：function_declarator -> declarator(params)
	if declType == "function_declarator" {
		if core.SafeChildCount(declarator) >= 1 {
			return d.extractDeclaratorName(ctx, core.SafeChild(declarator, 0))
		}
	}

	return ""
}

// processForLoopDeclaration 处理 for 循环中的声明
func (d *UninitVarSSADetector) processForLoopDeclaration(ctx *core.AnalysisContext, forNode *sitter.Node, state *SSAState) {
	// for (init; condition; increment)
	for i := 0; i < int(core.SafeChildCount(forNode)); i++ {
		child := core.SafeChild(forNode, i)
		if core.SafeType(child) == "declaration" {
			d.processDeclaration(ctx, child, state)
		}
	}
}

// performDataflowAnalysis 执行数据流分析（跟踪初始化状态）
func (d *UninitVarSSADetector) performDataflowAnalysis(ctx *core.AnalysisContext, node *sitter.Node, state *SSAState) {
	if node == nil {
		return
	}

	nodeType := core.SafeType(node)

	switch nodeType {
	case "assignment_expression":
		d.processAssignment(ctx, node, state)
	case "call_expression":
		d.processCallExpression(ctx, node, state)
	case "if_statement":
		d.processIfStatement(ctx, node, state)
		return // 已处理子节点
	case "switch_statement":
		d.processSwitchStatement(ctx, node, state)
		return // 已处理子节点
	}

	// 检查结构体成员赋值 (struct.field = value)
	if d.isStructMemberAssignment(ctx, node) {
		varName := d.extractStructBaseName(ctx, node)
		if varName != "" {
			state.partiallyInitialized[varName] = true
			// 部分初始化也算初始化（保守）
			state.initialized[varName] = true
			delete(state.uninitializedVars, varName)
		}
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if core.SafeType(child) != "function_definition" {
			d.performDataflowAnalysis(ctx, child, state)
		}
	}
}

// processAssignment 处理赋值表达式
func (d *UninitVarSSADetector) processAssignment(ctx *core.AnalysisContext, assignNode *sitter.Node, state *SSAState) {
	// assignment_expression: left = right
	if core.SafeChildCount(assignNode) < 3 {
		return
	}

	left := core.SafeChild(assignNode, 0)
	op := core.SafeChild(assignNode, 1)

	if core.SafeType(op) != "=" {
		return
	}

	// 获取被赋值的变量名（使用 extractDeclaratorName 处理复杂情况）
	varName := d.extractDeclaratorName(ctx, left)
	if varName == "" {
		// 尝试直接提取标识符
		if core.SafeType(left) == "identifier" {
			varName = ctx.GetSourceText(left)
		}
	}

	if varName != "" {
		state.initialized[varName] = true
		delete(state.uninitializedVars, varName)
	}
}

// isStructMemberAssignment 检查是否是结构体成员赋值 (struct.field = value)
func (d *UninitVarSSADetector) isStructMemberAssignment(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil || core.SafeType(node) != "assignment_expression" {
		return false
	}

	if core.SafeChildCount(node) < 3 {
		return false
	}

	left := core.SafeChild(node, 0)
	op := core.SafeChild(node, 1)

	// 检查操作符是 =
	if op == nil || ctx.GetSourceText(op) != "=" {
		return false
	}

	// 检查左侧是 field_expression (struct.field)
	return core.SafeType(left) == "field_expression"
}

// extractStructBaseName 从结构体成员表达式中提取结构体变量名
func (d *UninitVarSSADetector) extractStructBaseName(ctx *core.AnalysisContext, node *sitter.Node) string {
	// node 应该是 field_expression
	if node == nil || core.SafeType(node) != "field_expression" {
		return ""
	}

	// field_expression: object . property
	// 第一个子节点是 object (结构体变量)
	if core.SafeChildCount(node) >= 1 {
		object := core.SafeChild(node, 0)
		// object 可能是 identifier
		if core.SafeType(object) == "identifier" {
			return ctx.GetSourceText(object)
		}
	}

	return ""
}

// processCallExpression 处理函数调用
func (d *UninitVarSSADetector) processCallExpression(ctx *core.AnalysisContext, callNode *sitter.Node, state *SSAState) {
	// 检查是否是可能初始化变量的函数
	funcName := d.extractFunctionName(ctx, callNode)

	// 初始化函数：memset, memcpy, scanf, fgets, read, recv
	initFuncs := map[string]bool{
		"memset":  true,
		"memcpy":  true,
		"memmove": true,
		"scanf":   true,
		"fscanf":  true,
		"sscanf":  true,
		"fgets":   true,
		"read":    true,
		"recv":    true,
	}

	if initFuncs[funcName] && core.SafeChildCount(callNode) >= 2 {
		// 第一个参数可能被初始化
		args := core.SafeChild(callNode, 1)
		if core.SafeType(args) == "argument_list" && core.SafeChildCount(args) >= 1 {
			firstArg := core.SafeChild(args, 0)
			varName := d.extractDeclaratorName(ctx, firstArg)
			if varName == "" && core.SafeType(firstArg) == "identifier" {
				varName = ctx.GetSourceText(firstArg)
			}
			if varName != "" {
				state.initialized[varName] = true
				delete(state.uninitializedVars, varName)
			}
		}
	}

	// 通用启发式：检查所有参数中的取地址操作 (&var)
	// 如果变量通过取地址传递给函数，保守地认为它可能被初始化
	if core.SafeChildCount(callNode) >= 2 {
		args := core.SafeChild(callNode, 1)
		if core.SafeType(args) == "argument_list" {
			d.processAddressOfArguments(ctx, args, state)
		}
	}
}

// processAddressOfArguments 处理取地址参数
func (d *UninitVarSSADetector) processAddressOfArguments(ctx *core.AnalysisContext, argList *sitter.Node, state *SSAState) {
	for i := 0; i < int(core.SafeChildCount(argList)); i++ {
		arg := core.SafeChild(argList, i)
		if arg == nil {
			continue
		}

		// 检查是否是取地址表达式 (&var)
		if d.isAddressOfExpression(ctx, arg) {
			// 提取被取地址的变量名
			varName := d.extractAddressedVariable(ctx, arg)
			if varName != "" {
				// 保守策略：变量通过取地址传递给函数，可能被初始化
				state.initialized[varName] = true
				delete(state.uninitializedVars, varName)
			} else {
				// 尝试直接从源代码中提取
				argText := ctx.GetSourceText(arg)
				if len(argText) > 1 && argText[0] == '&' {
					varName = argText[1:]
					state.initialized[varName] = true
					delete(state.uninitializedVars, varName)
				}
			}
		}

		// 检查是否是标识符（数组名作为参数传递）
		if core.SafeType(arg) == "identifier" {
			varName := ctx.GetSourceText(arg)
			// 检查这个变量是否是数组类型（通过声明判断）
			if declNode, exists := state.declarations[varName]; exists {
				// 简化判断：如果声明中有 array_declarator，则认为是数组
				if d.isArrayDeclarator(declNode) {
					// 数组作为参数传递（退化为指针），可能被初始化
					state.initialized[varName] = true
					delete(state.uninitializedVars, varName)
				}
			}
		}
	}
}

// isArrayDeclarator 检查声明是否是数组类型
func (d *UninitVarSSADetector) isArrayDeclarator(declNode *sitter.Node) bool {
	if declNode == nil {
		return false
	}

	nodeType := core.SafeType(declNode)

	// 直接是数组声明符
	if nodeType == "array_declarator" {
		return true
	}

	// 检查子节点中是否有 array_declarator
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if d.isArrayDeclarator(child) {
			return true
		}
	}

	return false
}

// isAddressOfExpression 检查是否是取地址表达式 (&var)
func (d *UninitVarSSADetector) isAddressOfExpression(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}
	nodeType := core.SafeType(node)

	// Tree-sitter C grammar: &var 是 pointer_expression
	// pointer_expression: & operand
	if nodeType == "pointer_expression" {
		return true
	}

	// 兼容: 某些语法可能使用 unary_expression
	if nodeType == "unary_expression" && core.SafeChildCount(node) >= 1 {
		op := core.SafeChild(node, 0)
		if op != nil && ctx.GetSourceText(op) == "&" {
			return true
		}
	}

	return false
}

// extractAddressedVariable 从取地址表达式中提取变量名
func (d *UninitVarSSADetector) extractAddressedVariable(ctx *core.AnalysisContext, addrOfNode *sitter.Node) string {
	if addrOfNode == nil {
		return ""
	}

	nodeType := core.SafeType(addrOfNode)

	// pointer_expression: operand 是第一个子节点
	if nodeType == "pointer_expression" && core.SafeChildCount(addrOfNode) >= 1 {
		operand := core.SafeChild(addrOfNode, 0)
		return d.extractDeclaratorName(ctx, operand)
	}

	// unary_expression (&): operand 是第二个子节点
	if nodeType == "unary_expression" && core.SafeChildCount(addrOfNode) >= 2 {
		operand := core.SafeChild(addrOfNode, 1)
		return d.extractDeclaratorName(ctx, operand)
	}

	return ""
}

// scanUninitializedUses 扫描未初始化变量的使用（高置信度过滤）
// 只报告声明后立即使用，中间没有条件分支的情况
func (d *UninitVarSSADetector) scanUninitializedUses(ctx *core.AnalysisContext, node *sitter.Node, state *SSAState, vulns *[]core.DetectorVulnerability) {
	if node == nil {
		return
	}

	nodeType := core.SafeType(node)

	// 【数组下标检测】检查数组元素访问 arr[index]
	if nodeType == "subscript_expression" {
		// subscript_expression: array [index]
		if core.SafeChildCount(node) >= 1 {
			arrayNode := core.SafeChild(node, 0)
			arrayType := core.SafeType(arrayNode)

			// 获取数组名
			var arrayName string
			if arrayType == "identifier" {
				arrayName = ctx.GetSourceText(arrayNode)
			} else {
				// 处理更复杂的情况，如 field_expression (struct.array[index])
				arrayName = d.extractDeclaratorName(ctx, arrayNode)
			}

			// 检查数组是否未初始化
			if arrayName != "" && state.uninitializedVars[arrayName] && !state.initialized[arrayName] {
				if !d.isInDeclaration(node) && d.isDangerousUse(ctx, node) {
					// 检查是否是高置信度的未初始化使用
					if d.isHighConfidenceUninitialized(ctx, node, state, arrayName) {
						vuln := d.BaseDetector.CreateVulnerability(
							"CWE-457",
							fmt.Sprintf("Array '%s' may be used uninitialized (element access) at line %d", arrayName, int(node.StartPoint().Row)+1),
							node,
							core.ConfidenceMedium,
							core.SeverityMedium,
						)
						*vulns = append(*vulns, vuln)
					}
				}
			}
		}
	}

	// 检查标识符使用
	if nodeType == "identifier" {
		varName := ctx.GetSourceText(node)

		// 检查是否是未初始化变量
		if state.uninitializedVars[varName] && !state.initialized[varName] {
			// 确保不是声明本身
			if !d.isInDeclaration(node) && d.isDangerousUse(ctx, node) {
				// 【高置信度过滤】检查变量使用点和声明点之间是否有条件控制流
				if d.isHighConfidenceUninitialized(ctx, node, state, varName) {
					vuln := d.BaseDetector.CreateVulnerability(
						"CWE-457",
						fmt.Sprintf("Variable '%s' may be used uninitialized at line %d", varName, int(node.StartPoint().Row)+1),
						node,
						core.ConfidenceMedium,
						core.SeverityMedium,
					)
					*vulns = append(*vulns, vuln)
				}
			}
		}
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if core.SafeType(child) != "function_definition" {
			d.scanUninitializedUses(ctx, child, state, vulns)
		}
	}
}

// isHighConfidenceUninitialized 检查是否是高置信度的未初始化使用
// 返回 true 表示确实可能未初始化（应该报告）
// 返回 false 表示可能是条件初始化导致的误报（不报告）
func (d *UninitVarSSADetector) isHighConfidenceUninitialized(ctx *core.AnalysisContext, useNode *sitter.Node, state *SSAState, varName string) bool {
	// 获取变量声明节点
	declNode, exists := state.declarations[varName]
	if !exists {
		return true // 没有声明信息，保守报告
	}

	// 【宏初始化模式检测】检查变量是否在循环中被宏调用初始化
	if d.isMacroInitializationPattern(ctx, useNode, varName) {
		return false // 宏初始化模式，不报告
	}

	// 【循环赋值检测】检查变量是否在循环中被赋值
	// 基于 LLVM 2024 循环处理改进：循环后失效所有在循环中可能被写入的变量
	if d.isVariableAssignedInLoop(ctx, useNode, varName) {
		return false // 循环中赋值，可能是循环初始化模式，不报告
	}

	// 获取声明和使用的行号
	declLine := int(declNode.StartPoint().Row)
	useLine := int(useNode.StartPoint().Row)

	// 如果使用点和声明点在同一行，很可能是立即使用（高置信度）
	if declLine == useLine {
		return true
	}

	// 【改进的控制流检测】
	// 检查声明和使用点之间是否有控制流
	hasControlFlowBetween := d.hasControlFlowBetween(ctx, declNode, useNode)

	if !hasControlFlowBetween {
		// 没有控制流，这是真正的未初始化使用
		return true
	}

	// 【有控制流的情况】需要更精细的分析
	// 1. 检查变量是否在声明后被明确赋值（在任何路径上）
	// 2. 如果在声明后的某些路径上没有被赋值，仍然报告

	// 检查变量是否在同一作用域内、在声明后被赋值过
	// 如果从未赋值过，肯定要报告
	if state.initialized[varName] {
		// 变量在某个路径上被初始化了
		// 但仍需检查是否所有路径都初始化了
		// 如果在当前状态下仍被认为未初始化，说明不是所有路径都初始化
		if state.uninitializedVars[varName] {
			// 数据流分析认为变量仍可能未初始化
			// 这意味着不是所有路径都初始化了，应该报告
			return true
		}
		// 所有路径都初始化了，不报告
		return false
	}

	// 变量从未在任何路径上被初始化，应该报告
	return true
}

// isMacroInitializationPattern 检查是否是宏初始化模式
// 模式：变量在循环中通过宏调用（如 HOST_c2l）被初始化
func (d *UninitVarSSADetector) isMacroInitializationPattern(ctx *core.AnalysisContext, useNode *sitter.Node, varName string) bool {
	// 查找使用点的父节点
	parent := useNode.Parent()
	if parent == nil {
		return false
	}

	// 检查是否在循环中
	isInLoop := d.isInsideLoop(useNode)
	if !isInLoop {
		return false
	}

	// 检查父节点类型
	parentType := core.SafeType(parent)

	// 情况1：直接是 call_expression 的子节点
	if parentType == "call_expression" {
		funcName := d.extractFunctionName(ctx, parent)
		if funcName != "" && d.isLikelyInitMacro(funcName) {
			return true
		}
	}

	// 情况2：在 argument_list 中（作为宏的参数）
	if parentType == "argument_list" {
		// 获取 argument_list 的父节点
		grandParent := parent.Parent()
		if grandParent != nil && core.SafeType(grandParent) == "call_expression" {
			funcName := d.extractFunctionName(ctx, grandParent)
			if funcName != "" && d.isLikelyInitMacro(funcName) {
				// 检查变量是否作为输出参数（通常是第二个或后续参数）
				return d.isOutputParameter(useNode, parent)
			}
		}
	}

	return false
}

// isOutputParameter 检查参数是否是输出参数
func (d *UninitVarSSADetector) isOutputParameter(paramNode *sitter.Node, argList *sitter.Node) bool {
	// 获取参数在参数列表中的位置
	paramIndex := -1
	for i := 0; i < int(core.SafeChildCount(argList)); i++ {
		child := core.SafeChild(argList, i)
		if child == paramNode {
			paramIndex = i
			break
		}
	}

	// 如果是第二个或后续参数（索引 >= 1），可能是输出参数
	return paramIndex >= 1
}

// isInsideLoop 检查节点是否在循环内
func (d *UninitVarSSADetector) isInsideLoop(node *sitter.Node) bool {
	parent := node.Parent()
	depth := 0
	maxDepth := 15

	for parent != nil && depth < maxDepth {
		parentType := core.SafeType(parent)
		if parentType == "for_statement" ||
			parentType == "while_statement" ||
			parentType == "do_statement" {
			return true
		}
		parent = parent.Parent()
		depth++
	}

	return false
}

// isLikelyInitMacro 检查函数名是否可能是初始化宏
func (d *UninitVarSSADetector) isLikelyInitMacro(funcName string) bool {
	// 常见的初始化宏模式（基于 OpenSSL 代码）
	// 这些宏通常通过指针参数写入值
	initMacros := []string{
		"HOST_c2l",     // OpenSSL: convert from char to long
		"HOST_l2c",     // OpenSSL: convert from long to char
		"HOST_c2ln",    // OpenSSL: convert n chars
		"LOAD_",        // Various LOAD_* macros
		"GET_",         // Various GET_* macros
		"READ_",        // Various READ_* macros
		"asm volatile", // Inline assembly that writes to variable
	}

	for _, pattern := range initMacros {
		if len(funcName) >= len(pattern) {
			// 检查前缀匹配
			if funcName[:len(pattern)] == pattern {
				return true
			}
		}
	}

	// 检查是否是大写的宏名（C 宏通常是大写）
	if len(funcName) > 0 && funcName[0] >= 'A' && funcName[0] <= 'Z' {
		// 大写开头的函数名很可能是宏
		// 检查是否包含下划线（宏命名惯例）
		for i := 0; i < len(funcName); i++ {
			if funcName[i] == '_' {
				return true
			}
		}
	}

	return false
}

// hasControlFlowBetween 检查两个节点之间是否有控制流（if/switch/for/while）
func (d *UninitVarSSADetector) hasControlFlowBetween(ctx *core.AnalysisContext, startNode *sitter.Node, endNode *sitter.Node) bool {
	// 获取共同祖先节点
	commonAncestor := d.findCommonAncestor(startNode, endNode)
	if commonAncestor == nil {
		return false
	}

	// 检查共同祖先中是否有条件语句
	return d.containsControlFlow(commonAncestor)
}

// findCommonAncestor 查找两个节点的共同祖先
func (d *UninitVarSSADetector) findCommonAncestor(node1, node2 *sitter.Node) *sitter.Node {
	if node1 == nil || node2 == nil {
		return nil
	}

	// 收集 node1 的所有祖先
	ancestors1 := make(map[*sitter.Node]bool)
	p := node1
	for p != nil {
		ancestors1[p] = true
		p = p.Parent()
	}

	// 从 node2 向上找，找到第一个在 ancestors1 中的节点
	p = node2
	for p != nil {
		if ancestors1[p] {
			return p
		}
		p = p.Parent()
	}

	return nil
}

// containsControlFlow 检查子树中是否包含控制流语句
func (d *UninitVarSSADetector) containsControlFlow(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	nodeType := core.SafeType(node)

	// 检查是否是控制流语句
	switch nodeType {
	case "if_statement", "else_clause", "switch_statement",
		"for_statement", "while_statement", "do_statement",
		"conditional_expression":
		return true
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if d.containsControlFlow(child) {
			return true
		}
	}

	return false
}

// isVariableAssignedInLoop 检查变量是否在循环中被赋值
// 基于 LLVM 2024 循环处理改进：循环后失效所有在循环中可能被写入的变量
func (d *UninitVarSSADetector) isVariableAssignedInLoop(ctx *core.AnalysisContext, useNode *sitter.Node, varName string) bool {
	// 查找使用点所在的循环
	loopNode := d.findNearestLoop(useNode)
	if loopNode == nil {
		return false // 不在循环中
	}

	// 检查循环体中是否有对变量的赋值
	return d.hasVariableAssignmentInNode(ctx, loopNode, varName)
}

// findNearestLoop 查找最近的循环节点
func (d *UninitVarSSADetector) findNearestLoop(node *sitter.Node) *sitter.Node {
	parent := node.Parent()
	depth := 0
	maxDepth := 15

	for parent != nil && depth < maxDepth {
		parentType := core.SafeType(parent)
		if parentType == "for_statement" ||
			parentType == "while_statement" ||
			parentType == "do_statement" {
			return parent
		}
		parent = parent.Parent()
		depth++
	}

	return nil
}

// hasVariableAssignmentInNode 检查节点子树中是否有对指定变量的赋值
func (d *UninitVarSSADetector) hasVariableAssignmentInNode(ctx *core.AnalysisContext, node *sitter.Node, varName string) bool {
	if node == nil {
		return false
	}

	nodeType := core.SafeType(node)

	// 检查赋值表达式
	if nodeType == "assignment_expression" {
		// 检查左侧是否是目标变量
		left := core.SafeChild(node, 0)
		if left != nil {
			leftType := core.SafeType(left)
			if leftType == "identifier" {
				if ctx.GetSourceText(left) == varName {
					return true // 找到赋值
				}
			}
		}
	}

	// 检查逗号表达式中的赋值（如 int a = b, c = d;）
	if nodeType == "comma_expression" || nodeType == "declaration" {
		// 递归检查子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if d.hasVariableAssignmentInNode(ctx, child, varName) {
				return true
			}
		}
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		// 跳过嵌套的函数定义和循环（避免过度深入）
		childType := core.SafeType(child)
		if childType != "function_definition" &&
			childType != "for_statement" &&
			childType != "while_statement" &&
			childType != "do_statement" {
			if d.hasVariableAssignmentInNode(ctx, child, varName) {
				return true
			}
		}
	}

	return false
}

// ========== 辅助方法 ==========

// extractIdentifierText 提取标识符文本
func (d *UninitVarSSADetector) extractIdentifierText(ctx *core.AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return ""
	}

	nodeType := core.SafeType(node)

	if nodeType == "identifier" {
		return ctx.GetSourceText(node)
	}

	// 递归查找标识符
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if core.SafeType(child) == "identifier" {
			return ctx.GetSourceText(child)
		}
	}

	return ""
}

// extractFunctionName 提取函数名
func (d *UninitVarSSADetector) extractFunctionName(ctx *core.AnalysisContext, callNode *sitter.Node) string {
	if callNode == nil || core.SafeChildCount(callNode) < 1 {
		return ""
	}

	funcNode := core.SafeChild(callNode, 0)
	if funcNode == nil {
		return ""
	}

	funcType := core.SafeType(funcNode)

	if funcType == "identifier" {
		return ctx.GetSourceText(funcNode)
	}

	if funcType == "field_expression" {
		// obj.func -> 提取 func 部分
		for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
			child := core.SafeChild(funcNode, i)
			if core.SafeType(child) == "property_identifier" || core.SafeType(child) == "identifier" {
				return ctx.GetSourceText(child)
			}
		}
	}

	return ""
}

// isStaticStorage 检查是否是静态存储（static 或全局变量）
// 静态存储变量默认初始化为0，不需要报告未初始化
func (d *UninitVarSSADetector) isStaticStorage(declarator *sitter.Node) bool {
	if declarator == nil {
		return false
	}

	// 向上查找 declaration 节点（包含存储类说明符）
	parent := declarator.Parent()
	depth := 0
	maxDepth := 5

	for parent != nil && depth < maxDepth {
		parentType := core.SafeType(parent)

		if parentType == "declaration" {
			// 检查声明是否有 storage_class_specifier (static, extern, etc.)
			return d.hasStaticStorageClass(parent)
		}

		parent = parent.Parent()
		depth++
	}

	// 如果没有找到 declaration 节点，检查是否是全局变量
	// 全局变量不在任何函数定义内，默认初始化为0
	return !d.isInsideFunction(declarator)
}

// hasStaticStorageClass 检查声明是否有静态存储类说明符
func (d *UninitVarSSADetector) hasStaticStorageClass(declNode *sitter.Node) bool {
	if declNode == nil {
		return false
	}

	// 遍历声明的子节点，查找 storage_class_specifier
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if core.SafeType(child) == "storage_class_specifier" {
			// storage_class_specifier 的第一个子节点就是关键字文本
			// 直接检查子节点数量和类型
			if core.SafeChildCount(child) > 0 {
				// 获取实际的存储类说明符节点
				specNode := core.SafeChild(child, 0)
				if specNode != nil {
					// 通过检查节点类型或内容来判断
					// Tree-sitter 的 storage_class_specifier 子节点是 identifier 或 keyword
					specType := core.SafeType(specNode)
					// 大多数情况下，说明符直接是关键字
					if specType == "static" || specType == "extern" {
						return true
					}
				}
			}
			// 只要有 storage_class_specifier 就认为是静态存储
			// 因为 register 和 typedef 在声明位置会被识别
			// 保守策略：所有 storage_class_specifier 都认为是静态存储
			return true
		}
	}

	return false
}

// isInsideFunction 检查节点是否在函数定义内
func (d *UninitVarSSADetector) isInsideFunction(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	parent := node.Parent()
	depth := 0
	maxDepth := 15

	for parent != nil && depth < maxDepth {
		if core.SafeType(parent) == "function_definition" {
			return true
		}
		parent = parent.Parent()
		depth++
	}

	return false
}

// isInDeclaration 检查是否在声明中（声明本身不算使用）
func (d *UninitVarSSADetector) isInDeclaration(node *sitter.Node) bool {
	parent := node.Parent()
	depth := 0
	maxDepth := 5

	for parent != nil && depth < maxDepth {
		parentType := core.SafeType(parent)
		if parentType == "declaration" ||
			parentType == "init_declarator" ||
			parentType == "parameter_list" ||
			parentType == "field_declaration" {
			return true
		}
		if parentType == "function_definition" {
			break
		}
		parent = parent.Parent()
		depth++
	}
	return false
}

// processIfStatement 处理 if 语句（控制流分析）
func (d *UninitVarSSADetector) processIfStatement(ctx *core.AnalysisContext, ifNode *sitter.Node, state *SSAState) {
	// if_statement: (if condition consequence (alternative)?
	// 结构: [condition] [consequence] [else/elif]

	// 保存当前状态
	savedState := d.cloneState(state)

	// 处理 consequence (then 分支)
	consequence := d.findChildByType(ifNode, "compound_statement")
	if consequence == nil {
		// 可能是单语句
		for i := 0; i < int(core.SafeChildCount(ifNode)); i++ {
			child := core.SafeChild(ifNode, i)
			childType := core.SafeType(child)
			if childType == "expression_statement" || childType == "return_statement" {
				consequence = child
				break
			}
		}
	}

	if consequence != nil {
		d.performDataflowAnalysis(ctx, consequence, state)
	}
	thenState := d.cloneState(state)

	// 恢复初始状态处理 else 分支
	d.restoreState(state, savedState)
	alternative := d.findChildByType(ifNode, "else_clause")
	if alternative != nil {
		// else_clause 中的 compound_statement
		for i := 0; i < int(core.SafeChildCount(alternative)); i++ {
			child := core.SafeChild(alternative, i)
			if core.SafeType(child) == "compound_statement" {
				d.performDataflowAnalysis(ctx, child, state)
				break
			}
		}
	}
	elseState := d.cloneState(state)

	// 合并状态：只有当两个分支都初始化了变量时，才认为已初始化
	d.mergeStates(state, thenState, elseState)

	// 继续处理后续节点
	for i := 0; i < int(core.SafeChildCount(ifNode)); i++ {
		child := core.SafeChild(ifNode, i)
		childType := core.SafeType(child)
		if childType != "if_statement" && childType != "compound_statement" && childType != "else_clause" {
			d.performDataflowAnalysis(ctx, child, state)
		}
	}
}

// processSwitchStatement 处理 switch 语句
func (d *UninitVarSSADetector) processSwitchStatement(ctx *core.AnalysisContext, switchNode *sitter.Node, state *SSAState) {
	// 检查是否有 default 分支
	hasDefault := false
	body := d.findChildByType(switchNode, "compound_statement")

	if body != nil {
		for i := 0; i < int(core.SafeChildCount(body)); i++ {
			child := core.SafeChild(body, i)
			if core.SafeType(child) == "case_statement" {
				// case_statement: [default] | (case value:)
				caseFirstChild := core.SafeChild(child, 0)
				if caseFirstChild != nil && core.SafeType(caseFirstChild) == "default" {
					hasDefault = true
					break
				}
			}
		}
	}

	// 保存当前状态
	savedState := d.cloneState(state)

	// 分析每个 case
	var allStates []*SSAState
	if body != nil {
		for i := 0; i < int(core.SafeChildCount(body)); i++ {
			child := core.SafeChild(body, i)
			if core.SafeType(child) == "case_statement" {
				d.restoreState(state, savedState)
				d.performDataflowAnalysis(ctx, child, state)
				allStates = append(allStates, d.cloneState(state))
			}
		}
	}

	// 合并状态到当前 state
	if !hasDefault && len(allStates) > 0 {
		// 没有 default：保守策略，保持未初始化状态不变
		// 因为某些值可能不匹配任何 case，导致变量未初始化
		// 恢复到 switch 前的状态
		d.restoreState(state, savedState)
	} else if hasDefault && len(allStates) > 0 {
		// 有 default，使用并集
		d.mergeMultipleStates(state, allStates)
	} else if len(allStates) == 0 {
		// 空 switch，保持原状态
	}
}

// ========== 控制流辅助方法 ==========

// cloneState 克隆 SSA 状态
func (d *UninitVarSSADetector) cloneState(state *SSAState) *SSAState {
	newState := &SSAState{
		declarations:         make(map[string]*sitter.Node),
		initialized:          make(map[string]bool),
		uninitializedVars:    make(map[string]bool),
		partiallyInitialized: make(map[string]bool),
	}
	for k, v := range state.declarations {
		newState.declarations[k] = v
	}
	for k, v := range state.initialized {
		newState.initialized[k] = v
	}
	for k, v := range state.uninitializedVars {
		newState.uninitializedVars[k] = v
	}
	for k, v := range state.partiallyInitialized {
		newState.partiallyInitialized[k] = v
	}
	return newState
}

// restoreState 恢复 SSA 状态
func (d *UninitVarSSADetector) restoreState(target, source *SSAState) {
	target.declarations = make(map[string]*sitter.Node)
	target.initialized = make(map[string]bool)
	target.uninitializedVars = make(map[string]bool)
	target.partiallyInitialized = make(map[string]bool)

	for k, v := range source.declarations {
		target.declarations[k] = v
	}
	for k, v := range source.initialized {
		target.initialized[k] = v
	}
	for k, v := range source.uninitializedVars {
		target.uninitializedVars[k] = v
	}
	for k, v := range source.partiallyInitialized {
		target.partiallyInitialized[k] = v
	}
}

// mergeStates 合并两个状态（用于 if-else）
func (d *UninitVarSSADetector) mergeStates(target, thenState, elseState *SSAState) {
	// 清空当前状态
	target.initialized = make(map[string]bool)
	target.uninitializedVars = make(map[string]bool)

	// 合并 declarations
	for k, v := range thenState.declarations {
		target.declarations[k] = v
	}
	for k, v := range elseState.declarations {
		if _, exists := target.declarations[k]; !exists {
			target.declarations[k] = v
		}
	}

	// 对于 initialized：只有两个分支都初始化了，才认为已初始化
	for k, v := range thenState.initialized {
		if elseState.initialized[k] && v {
			target.initialized[k] = true
		}
	}

	// 对于 uninitialized：任一分支未初始化，则认为可能未初始化
	for k, v := range thenState.uninitializedVars {
		if v || elseState.uninitializedVars[k] {
			target.uninitializedVars[k] = true
		}
	}
	for k, v := range elseState.uninitializedVars {
		if v || thenState.uninitializedVars[k] {
			target.uninitializedVars[k] = true
		}
	}
}

// mergeMultipleStates 合并多个状态（用于 switch 有 default）
func (d *UninitVarSSADetector) mergeMultipleStates(target *SSAState, states []*SSAState) {
	if len(states) == 0 {
		return
	}

	// 清空当前状态
	target.initialized = make(map[string]bool)
	target.uninitializedVars = make(map[string]bool)

	// 收集所有变量
	allVars := make(map[string]bool)
	for _, state := range states {
		for k := range state.declarations {
			allVars[k] = true
		}
	}

	// 对于每个变量，如果所有状态都初始化了，则认为已初始化
	for varName := range allVars {
		allInitialized := true
		anyUninitialized := false

		for _, state := range states {
			if !state.initialized[varName] {
				allInitialized = false
			}
			if state.uninitializedVars[varName] {
				anyUninitialized = true
			}
		}

		if allInitialized {
			target.initialized[varName] = true
		}
		if anyUninitialized || !allInitialized {
			target.uninitializedVars[varName] = true
		}
	}
}

// intersectStates 求交集（用于 switch 无 default）
func (d *UninitVarSSADetector) intersectStates(target *SSAState, states []*SSAState) {
	if len(states) == 0 {
		return
	}

	// 清空当前状态
	target.initialized = make(map[string]bool)
	target.uninitializedVars = make(map[string]bool)

	// 收集所有变量
	allVars := make(map[string]bool)
	for _, state := range states {
		for k := range state.declarations {
			allVars[k] = true
		}
	}

	// 只有所有 case 都初始化的变量才认为是安全的
	for varName := range allVars {
		allInitialized := true
		for _, state := range states {
			if !state.initialized[varName] {
				allInitialized = false
				break
			}
		}

		if allInitialized {
			target.initialized[varName] = true
		} else {
			target.uninitializedVars[varName] = true
		}
	}
}

// findChildByType 查找指定类型的子节点
func (d *UninitVarSSADetector) findChildByType(node *sitter.Node, nodeType string) *sitter.Node {
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if core.SafeType(child) == nodeType {
			return child
		}
	}
	return nil
}

// isDangerousUse 检查是否是危险的使用（2024 保守策略）
func (d *UninitVarSSADetector) isDangerousUse(ctx *core.AnalysisContext, node *sitter.Node) bool {
	parent := node.Parent()
	if parent == nil {
		return true
	}

	parentType := core.SafeType(parent)

	// 危险使用场景
	switch parentType {
	case "assignment_expression":
		// 赋值右侧使用是危险的
		left := core.SafeChild(parent, 0)
		return left != node

	case "call_expression":
		// 作为函数参数是危险的
		return true

	case "binary_expression":
		// 表达式中使用是危险的
		return true

	case "unary_expression":
		// 解引用、取地址等
		return true

	case "subscript_expression":
		// 数组索引使用是危险的
		return true

	case "return_statement":
		// 返回值使用是危险的
		return true

	case "conditional_expression":
		// 条件表达式中的使用
		return true

	default:
		// 保守：其他情况也报告
		return true
	}
}
