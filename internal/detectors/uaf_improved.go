package detectors

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// UAFDetectorImproved 改进的 Use After Free 检测器
// 主要改进：
// 1. 追踪内容复制操作 (malloc + strcpy)
// 2. 理解指针转移和所有权转移
// 3. 分析重新赋值操作
// 4. 区分函数内和跨函数的 UAF
// 5. 追踪参数传递到函数的复制关系
// 6. **基于CFG的路径可达性分析** - 只报告在同一可行路径上的UAF
type UAFDetectorImproved struct {
	*core.BaseDetector
	z3Solver       core.Z3Solver
	freedPointers  map[string]*FreedPointerInfo
	copiesMade     map[string]string // 原始指针 -> 副本指针
	// 跨函数追踪
	paramCopies    map[string]*ParamCopyInfo // 参数复制信息
	// CFG路径分析 - 每个函数的CFG
	functionCFGs   map[*sitter.Node]*core.CFG // 函数AST节点 -> CFG
}

// ParamCopyInfo 参数复制信息
type ParamCopyInfo struct {
	ParamName    string // 参数名
	FuncName     string // 接收函数名
	CopyVarName  string // 函数内的副本变量名
	CopyMade     bool   // 是否创建了副本
}

// FreedPointerInfo 被释放指针的信息
type FreedPointerInfo struct {
	VariableName    string
	FreeLine        int
	IsValid         bool // 是否为有效的释放（非误报）
	CopyTarget      string // 如果有副本，记录副本变量名
	Reassigned      bool // 释放后是否被重新赋值
	// *** 新增：结构体成员精确追踪 ***
	FieldAccessPath string // 精确的成员访问路径，例如 "zi->ci.central_header"
	IsStructMember  bool  // 是否是结构体成员的释放（例如 free(ptr->member)）
	// *** 新增：指针空值化追踪 ***
	Nullified      bool // 释放后是否被立即设置为NULL（安全化操作）
	NullifiedLine  int  // 设置为NULL的行号
}

// NewUAFDetectorImproved 创建改进的UAF检测器
func NewUAFDetectorImproved() *UAFDetectorImproved {
	return &UAFDetectorImproved{
		BaseDetector:   core.NewBaseDetector("UAF Detector", "CWE-416"),
		freedPointers:  make(map[string]*FreedPointerInfo),
		copiesMade:     make(map[string]string),
		paramCopies:    make(map[string]*ParamCopyInfo),
		functionCFGs:   make(map[*sitter.Node]*core.CFG),
	}
}

// Name 返回检测器名称
func (d *UAFDetectorImproved) Name() string {
	return d.BaseDetector.Name()
}

// Description 返回检测器描述
func (d *UAFDetectorImproved) Description() string {
	return "Detects use after free vulnerabilities with reduced false positives"
}

// Run 执行检测
func (d *UAFDetectorImproved) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 重置状态
	d.freedPointers = make(map[string]*FreedPointerInfo)
	d.copiesMade = make(map[string]string)
	d.paramCopies = make(map[string]*ParamCopyInfo)
	d.functionCFGs = make(map[*sitter.Node]*core.CFG)

	// 第一遍：收集跨函数参数复制关系
	d.collectParamCopyRelations(ctx)

	// 2. 查找所有函数定义
	functions, err := ctx.QueryNodes("(function_definition) @func")
	if err != nil {
		return nil, err
	}

	// 3. 为每个函数构建CFG并分析
	for _, funcNode := range functions {
		// 为该函数构建CFG
		cfg := d.buildFunctionCFG(ctx, funcNode)
		if cfg != nil {
			d.functionCFGs[funcNode] = cfg
		}
	}

	// 4. 分析每个函数（现在有了CFG）
	for _, funcNode := range functions {
		d.analyzeFunction(ctx, funcNode, &vulns)
	}

	return vulns, nil
}

// buildFunctionCFG 为单个函数构建控制流图（CFG）
// 这是路径敏感性分析的基础
func (d *UAFDetectorImproved) buildFunctionCFG(ctx *core.AnalysisContext, funcNode *sitter.Node) *core.CFG {
	// 创建新的CFG
	cfg := core.NewCFG()

	// 创建函数入口节点
	entry := d.createCFGNode(cfg, core.BlockEntry, funcNode)
	cfg.Entry = entry

	// 创建函数退出节点
	exit := d.createCFGNode(cfg, core.BlockExit, nil)
	cfg.Exit = exit

	// 递归构建CFG
	d.buildNodeCFG(ctx, funcNode, entry, cfg, exit)

	// 确保所有未连接的节点都连接到exit
	d.connectToExit(cfg, exit)

	return cfg
}

// createCFGNode 创建CFG节点
func (d *UAFDetectorImproved) createCFGNode(cfg *core.CFG, nodeType core.BlockType, astNode *sitter.Node) *core.CFGNode {
	node := &core.CFGNode{
		ID:          len(cfg.Nodes),
		Type:        nodeType,
		ASTNode:     astNode,
		Statements:  make([]*sitter.Node, 0),
		Predecessors: make([]*core.CFGNode, 0),
		Successors:   make([]*core.CFGNode, 0),
	}
	cfg.Nodes = append(cfg.Nodes, node)
	return node
}

// buildNodeCFG 递归构建节点的CFG
func (d *UAFDetectorImproved) buildNodeCFG(ctx *core.AnalysisContext, node *sitter.Node, entry *core.CFGNode, cfg *core.CFG, exit *core.CFGNode) *core.CFGNode {
	if node == nil {
		return entry
	}

	switch core.SafeType(node) {
	case "compound_statement":
		return d.buildCompoundStatement(ctx, node, entry, cfg)

	case "if_statement":
		return d.buildIfStatement(ctx, node, entry, cfg)

	case "for_statement", "while_statement", "do_statement":
		return d.buildLoopStatement(ctx, node, entry, cfg)

	case "switch_statement":
		return d.buildSwitchStatement(ctx, node, entry, cfg)

	case "return_statement", "break_statement":
		return d.buildControlTransfer(node, entry, cfg, exit)

	default:
		// 普通语句
		if d.isStatement(node) {
			return d.buildStatement(node, entry, cfg)
		}

		// 递归处理子节点
		lastNode := entry
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if child != nil {
				lastNode = d.buildNodeCFG(ctx, child, lastNode, cfg, exit)
			}
		}
		return lastNode
	}
}

// buildCompoundStatement 构建复合语句的CFG
func (d *UAFDetectorImproved) buildCompoundStatement(ctx *core.AnalysisContext, node *sitter.Node, entry *core.CFGNode, cfg *core.CFG) *core.CFGNode {
	lastNode := entry

	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if child != nil && d.isStatement(child) {
			lastNode = d.buildNodeCFG(ctx, child, lastNode, cfg, cfg.Exit)
		}
	}

	return lastNode
}

// buildIfStatement 构建if语句的CFG
func (d *UAFDetectorImproved) buildIfStatement(ctx *core.AnalysisContext, node *sitter.Node, entry *core.CFGNode, cfg *core.CFG) *core.CFGNode {
	// 创建条件节点
	conditionNode := core.SafeChildByFieldName(node, "condition")
	condition := d.createCFGNode(cfg, core.BlockCondition, conditionNode)
	condition.Condition = conditionNode
	d.addEdge(cfg, entry, condition)

	// 处理consequence分支（then部分）
	consequenceNode := core.SafeChildByFieldName(node, "consequence")
	consequenceEntry := d.createCFGNode(cfg, core.BlockBranch, consequenceNode)
	d.addEdge(cfg, condition, consequenceEntry)
	consequenceExit := d.buildNodeCFG(ctx, consequenceNode, consequenceEntry, cfg, cfg.Exit)

	// 处理alternative分支（else部分）
	var alternativeExit *core.CFGNode
	if alternativeNode := core.SafeChildByFieldName(node, "alternative"); alternativeNode != nil {
		alternativeEntry := d.createCFGNode(cfg, core.BlockBranch, alternativeNode)
		d.addEdge(cfg, condition, alternativeEntry)
		alternativeExit = d.buildNodeCFG(ctx, alternativeNode, alternativeEntry, cfg, cfg.Exit)

		// 创建汇聚点
		mergeNode := d.createCFGNode(cfg, core.BlockStatement, nil)
		if consequenceExit != nil {
			d.addEdge(cfg, consequenceExit, mergeNode)
		}
		if alternativeExit != nil {
			d.addEdge(cfg, alternativeExit, mergeNode)
		}
		return mergeNode
	} else {
		// 没有else分支
		mergeNode := d.createCFGNode(cfg, core.BlockStatement, nil)
		if consequenceExit != nil {
			d.addEdge(cfg, consequenceExit, mergeNode)
		}
		d.addEdge(cfg, condition, mergeNode)
		return mergeNode
	}
}

// buildLoopStatement 构建循环语句的CFG
func (d *UAFDetectorImproved) buildLoopStatement(ctx *core.AnalysisContext, node *sitter.Node, entry *core.CFGNode, cfg *core.CFG) *core.CFGNode {
	// 创建循环头节点
	loopHeader := d.createCFGNode(cfg, core.BlockLoop, node)
	d.addEdge(cfg, entry, loopHeader)

	// 创建条件节点
	var condition *core.CFGNode
	if conditionNode := core.SafeChildByFieldName(node, "condition"); conditionNode != nil {
		condition = d.createCFGNode(cfg, core.BlockCondition, conditionNode)
		condition.Condition = conditionNode
		d.addEdge(cfg, loopHeader, condition)
	} else {
		condition = loopHeader
	}

	// 处理循环体
	var bodyExit *core.CFGNode
	if bodyNode := core.SafeChildByFieldName(node, "body"); bodyNode != nil {
		bodyEntry := d.createCFGNode(cfg, core.BlockBranch, bodyNode)
		d.addEdge(cfg, condition, bodyEntry)
		bodyExit = d.buildNodeCFG(ctx, bodyNode, bodyEntry, cfg, cfg.Exit)

		// 循环体完成后回到循环头
		if bodyExit != nil {
			d.addEdge(cfg, bodyExit, loopHeader)
		}
	}

	// 创建循环出口节点
	loopExit := d.createCFGNode(cfg, core.BlockStatement, nil)
	d.addEdge(cfg, condition, loopExit)

	return loopExit
}

// buildSwitchStatement 构建switch语句的CFG
func (d *UAFDetectorImproved) buildSwitchStatement(ctx *core.AnalysisContext, node *sitter.Node, entry *core.CFGNode, cfg *core.CFG) *core.CFGNode {
	// 创建switch头节点
	switchHeader := d.createCFGNode(cfg, core.BlockCondition, node)
	d.addEdge(cfg, entry, switchHeader)

	// 处理各个case
	var lastCaseExit *core.CFGNode
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if child != nil && (core.SafeType(child) == "case_statement" || core.SafeType(child) == "default_statement") {
			caseNode := d.createCFGNode(cfg, core.BlockBranch, child)
			d.addEdge(cfg, switchHeader, caseNode)
			caseExit := d.buildNodeCFG(ctx, child, caseNode, cfg, cfg.Exit)

			if lastCaseExit != nil && caseExit != nil {
				d.addEdge(cfg, lastCaseExit, caseNode)
			}
			lastCaseExit = caseExit
		}
	}

	// 创建switch出口
	switchExit := d.createCFGNode(cfg, core.BlockStatement, nil)
	if lastCaseExit != nil {
		d.addEdge(cfg, lastCaseExit, switchExit)
	}
	d.addEdge(cfg, switchHeader, switchExit)

	return switchExit
}

// buildControlTransfer 构建控制转移语句的CFG
func (d *UAFDetectorImproved) buildControlTransfer(node *sitter.Node, entry *core.CFGNode, cfg *core.CFG, exit *core.CFGNode) *core.CFGNode {
	stmtNode := d.createCFGNode(cfg, core.BlockStatement, node)
	stmtNode.Statements = append(stmtNode.Statements, node)
	d.addEdge(cfg, entry, stmtNode)

	// 返回语句直接连接到函数退出节点
	if core.SafeType(node) == "return_statement" {
		d.addEdge(cfg, stmtNode, exit)
	}

	return stmtNode
}

// buildStatement 构建普通语句的CFG
func (d *UAFDetectorImproved) buildStatement(node *sitter.Node, entry *core.CFGNode, cfg *core.CFG) *core.CFGNode {
	stmtNode := d.createCFGNode(cfg, core.BlockStatement, node)
	stmtNode.Statements = append(stmtNode.Statements, node)
	d.addEdge(cfg, entry, stmtNode)
	return stmtNode
}

// connectToExit 确保所有未连接的节点都连接到exit
func (d *UAFDetectorImproved) connectToExit(cfg *core.CFG, exit *core.CFGNode) {
	for _, node := range cfg.Nodes {
		if node != exit && len(node.Successors) == 0 && node.Type != core.BlockExit {
			d.addEdge(cfg, node, exit)
		}
	}
}

// addEdge 添加CFG边
func (d *UAFDetectorImproved) addEdge(cfg *core.CFG, from, to *core.CFGNode) {
	from.Successors = append(from.Successors, to)
	to.Predecessors = append(to.Predecessors, from)
	cfg.Edges = append(cfg.Edges, [2]int{from.ID, to.ID})
}

// isStatement 判断节点是否是语句
func (d *UAFDetectorImproved) isStatement(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	nodeType := core.SafeType(node)
	switch nodeType {
	case "expression_statement", "declaration", "compound_statement",
		"return_statement", "break_statement", "continue_statement",
		"call_expression", "assignment_expression",
		"if_statement", "for_statement", "while_statement", "do_statement",
		"switch_statement", "case_statement", "default_statement":
		return true
	default:
		return false
	}
}

// collectParamCopyRelations 收集参数复制关系
// 针对 gzlib.c: path 被传给 gz_open 并在内部复制
func (d *UAFDetectorImproved) collectParamCopyRelations(ctx *core.AnalysisContext) {
	// 查找所有函数定义
	functions, _ := ctx.QueryNodes("(function_definition) @func")

	for _, funcNode := range functions {
		// 获取函数名
		funcName := d.getFunctionNameFromDef(ctx, funcNode)

		// 查找函数内的 malloc + strcpy/snprintf 模式
		// 检查是否有参数被复制
		d.analyzeParamCopiesInFunction(ctx, funcNode, funcName)
	}
}

// getFunctionNameFromDef 从函数定义节点获取函数名
func (d *UAFDetectorImproved) getFunctionNameFromDef(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
	declarator := core.SafeChildByFieldName(funcNode, "declarator")
	if declarator != nil {
		funcIdentifier := core.SafeChildByFieldName(declarator, "declarator")
		if funcIdentifier != nil && core.SafeType(funcIdentifier) == "identifier" {
			return ctx.GetSourceText(funcIdentifier)
		}
	}
	return ""
}

// analyzeParamCopiesInFunction 分析函数内的参数复制
func (d *UAFDetectorImproved) analyzeParamCopiesInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, funcName string) {
	// 获取函数参数列表
	params := d.extractFunctionParams(ctx, funcNode)
	if len(params) == 0 {
		return
	}

	// 在函数体内查找 malloc + strcpy/snprintf 模式
	body := core.SafeChildByFieldName(funcNode, "body")
	if body == nil {
		return
	}

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		// 查找 malloc 调用
		if core.SafeType(node) == "call_expression" {
			callFuncName := d.getFunctionName(ctx, node)
			if callFuncName == "malloc" || callFuncName == "calloc" {
				// 获取 malloc 的目标变量
				mallocTarget := d.extractMallocTarget(ctx, node)
				if mallocTarget == "" {
					// 递归子节点
					for i := 0; i < int(core.SafeChildCount(node)); i++ {
						traverse(core.SafeChild(node, i))
					}
					return
				}

				// 查找后续的 strcpy/snprintf 调用
				// 检查 strcpy/snprintf 的第二个参数是否是函数参数
				if d.findCopyFromParam(ctx, node, mallocTarget, params, funcName) {
					// 找到了参数复制模式
				}
			}
		}

		// 递归子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	traverse(body)
}

// extractFunctionParams 提取函数参数列表
func (d *UAFDetectorImproved) extractFunctionParams(ctx *core.AnalysisContext, funcNode *sitter.Node) []string {
	var params []string

	parameters := core.SafeChildByFieldName(funcNode, "parameters")
	if parameters == nil {
		return params
	}

	for i := 0; i < int(core.SafeChildCount(parameters)); i++ {
		child := core.SafeChild(parameters, i)
		if core.SafeType(child) == "parameter_declaration" {
			// 查找参数名
			declarator := core.SafeChildByFieldName(child, "declarator")
			if declarator != nil && core.SafeType(declarator) == "identifier" {
				paramName := ctx.GetSourceText(declarator)
				params = append(params, paramName)
			}
		}
	}

	return params
}

// findCopyFromParam 查找从参数复制的内容
// 返回是否找到参数复制模式
func (d *UAFDetectorImproved) findCopyFromParam(ctx *core.AnalysisContext, mallocNode *sitter.Node, mallocTarget string, params []string, funcName string) bool {
	mallocLine := int(mallocNode.StartPoint().Row)

	// 在 malloc 之后查找 strcpy/snprintf 调用（限制在10行内）
	parent := mallocNode.Parent()
	for parent != nil && core.SafeType(parent) != "function_definition" {
		parent = parent.Parent()
	}

	if parent == nil {
		return false
	}

	body := core.SafeChildByFieldName(parent, "body")
	if body == nil {
		return false
	}

	var found bool
	var traverse func(node *sitter.Node) bool
	traverse = func(node *sitter.Node) bool {
		if node == nil || found {
			return false
		}

		nodeLine := int(node.StartPoint().Row)
		// 只检查 malloc 后 10 行内的代码
		if nodeLine <= mallocLine || nodeLine > mallocLine+10 {
			// 继续遍历子节点
			for i := 0; i < int(core.SafeChildCount(node)); i++ {
				if traverse(core.SafeChild(node, i)) {
					return true
				}
			}
			return false
		}

		// 查找 strcpy/snprintf 调用
		if core.SafeType(node) == "call_expression" {
			callFuncName := d.getFunctionName(ctx, node)
			if callFuncName == "strcpy" || callFuncName == "snprintf" || callFuncName == "sprintf" {
				// 检查第一个参数是否是 malloc 的目标
				dstVar := d.extractStrcpyTarget(ctx, node)
				if dstVar == mallocTarget {
					// 检查第二个参数是否是函数参数
					args := core.SafeChildByFieldName(node, "arguments")
					if args != nil && core.SafeChildCount(args) >= 2 {
						// 第二个参数（跳过标点符号）
						var secondArg *sitter.Node
						argCount := 0
						for i := 0; i < int(core.SafeChildCount(args)); i++ {
							arg := core.SafeChild(args, i)
							if core.SafeType(arg) != "," && core.SafeType(arg) != "(" && core.SafeType(arg) != ")" {
								argCount++
								if argCount == 2 {
									secondArg = arg
									break
								}
							}
						}

						if secondArg != nil && core.SafeType(secondArg) == "identifier" {
							srcParam := ctx.GetSourceText(secondArg)
							// 检查是否是函数参数
							for _, param := range params {
								if param == srcParam {
									// 找到参数复制模式！
									// 记录：参数 srcParam 被复制到 mallocTarget
									_ = funcName + ":" + srcParam
									d.paramCopies[srcParam] = &ParamCopyInfo{
										ParamName:   srcParam,
										FuncName:    funcName,
										CopyVarName: mallocTarget,
										CopyMade:    true,
									}
									found = true
									return true
								}
							}
						}
					}
				}
			}
		}

		// 递归子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			if traverse(core.SafeChild(node, i)) {
				return true
			}
		}
		return false
	}

	traverse(body)
	return found
}

// analyzeFunction 分析单个函数
// 关键修复：每个函数使用独立的freedPointers map，避免跨函数误报
func (d *UAFDetectorImproved) analyzeFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, vulns *[]core.DetectorVulnerability) {
	// *** 关键修复：为每个函数创建独立的freedPointers map ***
	// 这样可以避免一个函数中的free被误认为是另一个函数中的UAF
	localFreedPointers := make(map[string]*FreedPointerInfo)
	localCopiesMade := make(map[string]string)

	// 获取函数名，用于调试
	funcName := d.getFunctionNameFromDef(ctx, funcNode)

	// 第一遍：查找赋值操作，追踪指针重新赋值（使用局部map）
	d.findReassignmentsInFunction(ctx, funcNode, localFreedPointers)

	// 第二遍：查找 malloc + strcpy 模式，追踪内容复制（使用局部map）
	d.findContentCopiesInFunction(ctx, funcNode, localCopiesMade)

	// 第三遍：查找 free 调用
	freeCalls := d.findFreeCalls(ctx, funcNode)

	// 第四遍：标记被释放的指针（存储在局部map中）
	for _, freeCall := range freeCalls {
		freedVar := d.getFreedVariable(ctx, freeCall)
		if freedVar != nil {
			// *** 新增：提取完整的访问路径 ***
			fullPath, isStructMember := d.getFullAccessPath(ctx, freedVar)
			varName := strings.TrimSpace(ctx.GetSourceText(freedVar))
			freeLine := int(freeCall.StartPoint().Row)

			// 使用完整路径作为key（如果存在结构体成员访问）
			mapKey := varName
			if isStructMember && fullPath != "" {
				mapKey = fullPath
			}

			localFreedPointers[mapKey] = &FreedPointerInfo{
				VariableName:    varName,
				FreeLine:        freeLine,
				IsValid:         true,
				Reassigned:      false,
				FieldAccessPath: fullPath,        // 记录完整路径
				IsStructMember:  isStructMember,  // 标记是否是结构体成员
			}
		}
	}

	// *** 新增：第五遍：检测指针空值化操作 (ptr = NULL) ***
	d.findNullificationOperations(ctx, funcNode, localFreedPointers)

	// 第六遍：查找所有使用并检查是否为UAF（传递局部map）
	d.findUsagesInFunction(ctx, funcNode, vulns, localFreedPointers, localCopiesMade, funcName)
}

// findReassignmentsInFunction 查找指针重新赋值操作（函数作用域版本）
func (d *UAFDetectorImproved) findReassignmentsInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, freedPointers map[string]*FreedPointerInfo) {
	visited := make(map[uintptr]bool)

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		if core.SafeType(node) == "assignment_expression" {
			left := core.SafeChildByFieldName(node, "left")
			right := core.SafeChildByFieldName(node, "right")

			if left != nil && core.SafeType(left) == "identifier" {
				varName := strings.TrimSpace(ctx.GetSourceText(left))

				if right != nil && d.hasMallocCall(ctx, right) {
					if info, exists := freedPointers[varName]; exists {
						info.Reassigned = true
						info.IsValid = false
					}
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}
}

// findContentCopiesInFunction 查找内容复制操作（函数作用域版本）
func (d *UAFDetectorImproved) findContentCopiesInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, copiesMade map[string]string) {
	visited := make(map[uintptr]bool)

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		if core.SafeType(node) == "call_expression" {
			funcName := d.getFunctionName(ctx, node)
			if funcName == "malloc" || funcName == "calloc" {
				varName := d.extractMallocTarget(ctx, node)
				if varName != "" {
					d.findStrcpyAfterMallocInFunction(ctx, funcNode, node, varName, copiesMade)
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}
}

// findStrcpyAfterMallocInFunction 在malloc后查找strcpy（函数作用域版本）
func (d *UAFDetectorImproved) findStrcpyAfterMallocInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, mallocNode *sitter.Node, srcVar string, copiesMade map[string]string) {
	mallocLine := int(mallocNode.StartPoint().Row)

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeLine := int(node.StartPoint().Row)
		if nodeLine <= mallocLine || nodeLine > mallocLine+5 {
			for i := 0; i < int(core.SafeChildCount(node)); i++ {
				traverse(core.SafeChild(node, i))
			}
			return
		}

		if core.SafeType(node) == "call_expression" {
			funcName := d.getFunctionName(ctx, node)
			if funcName == "strcpy" || funcName == "memcpy" || funcName == "strncpy" {
				dstVar := d.extractStrcpyTarget(ctx, node)
				if dstVar == srcVar {
					srcVar := d.extractMallocTarget(ctx, mallocNode)
					dstVar := d.extractStrcpyTarget(ctx, node)
					if srcVar != "" && dstVar != "" && srcVar != dstVar {
						copiesMade[srcVar] = dstVar
					}
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}
}

// findUsagesInFunction 查找变量使用（函数作用域版本）
func (d *UAFDetectorImproved) findUsagesInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, vulns *[]core.DetectorVulnerability, freedPointers map[string]*FreedPointerInfo, copiesMade map[string]string, funcName string) {
	funcStartLine := int(funcNode.StartPoint().Row)

	visited := make(map[uintptr]bool)

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		nodeLine := int(node.StartPoint().Row)

		if d.isUsage(node) {
			varName := d.extractVariableName(ctx, node)
			if varName == "" {
				for i := 0; i < int(core.SafeChildCount(node)); i++ {
					traverse(core.SafeChild(node, i))
				}
				return
			}

			// *** 关键改进：结构体成员精确匹配 ***
			usageFullPath, _ := d.getFullAccessPath(ctx, node)

			// 首先尝试精确路径匹配（例如 "zi->ci.central_header"）
			if usageFullPath != "" {
				if info, exists := freedPointers[usageFullPath]; exists && info.IsValid {
					isAfterFree := nodeLine > info.FreeLine
					if d.shouldReportUAFForFunction(ctx, funcNode, usageFullPath, node, nodeLine, funcStartLine, info, isAfterFree, copiesMade) {
						vuln := d.BaseDetector.CreateVulnerability(
							core.CWE416,
							fmt.Sprintf("Variable '%s' used after free (line %d freed, used at line %d)", usageFullPath, info.FreeLine+1, nodeLine+1),
							node,
							core.ConfidenceMedium,
							core.SeverityCritical,
						)
						*vulns = append(*vulns, vuln)
					}
					return // 精确匹配后直接返回
				}
			}

			// 后备：简单变量名匹配（只针对非结构体成员free）
			if info, exists := freedPointers[varName]; exists && info.IsValid {
				// *** 关键过滤：如果free的是结构体成员，简单变量名匹配跳过 ***
				if info.IsStructMember {
					// free(zi->ci.central_header) 后使用 zi 是安全的
					// 只有精确匹配 zi->ci.central_header 才是UAF
					return
				}

				isAfterFree := nodeLine > info.FreeLine

				if d.shouldReportUAFForFunction(ctx, funcNode, varName, node, nodeLine, funcStartLine, info, isAfterFree, copiesMade) {
					vuln := d.BaseDetector.CreateVulnerability(
						core.CWE416,
						fmt.Sprintf("Variable '%s' used after free (line %d freed, used at line %d)", varName, info.FreeLine+1, nodeLine+1),
						node,
						core.ConfidenceMedium,
						core.SeverityCritical,
					)
					*vulns = append(*vulns, vuln)
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	traverse(core.SafeChildByFieldName(funcNode, "body"))
}

// shouldReportUAFForFunction 判断是否应该报告UAF（函数作用域版本）
func (d *UAFDetectorImproved) shouldReportUAFForFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, varName string, usageNode *sitter.Node, usageLine, funcStartLine int, info *FreedPointerInfo, isAfterFree bool, copiesMade map[string]string) bool {
	if !isAfterFree {
		return false
	}

	if info.Reassigned {
		return false
	}

	// 检查内容复制（使用局部map）
	if _, hasCopy := copiesMade[varName]; hasCopy {
		return false
	}

	// *** 新增：提前返回检测 ***
	// 如果 free 后有 return（在错误处理分支），usage 不可达
	if d.checkEarlyReturnAfterFree(ctx, funcNode, info.FreeLine, usageLine) {
		return false // 路径不可达，不报告
	}

	// CFG路径可达性检查
	cfg, hasCFG := d.functionCFGs[funcNode]
	if hasCFG && cfg != nil {
		freeBlock := d.findBlockContainingLine(cfg, info.FreeLine)
		usageBlock := d.findBlockContainingLine(cfg, usageLine)

		if freeBlock != nil && usageBlock != nil {
			if !d.isPathReachableInCFG(freeBlock, usageBlock) {
				return false
			}
		}
	}

	if d.isFunctionParameter(ctx, varName, funcStartLine) {
		return true
	}

	if strings.Contains(varName, "->") || strings.Contains(varName, ".") {
		return true
	}

	distance := usageLine - info.FreeLine
	if distance > 100 {
		return false
	}

	if d.hasGuardClause(ctx, usageNode, varName) {
		return false
	}

	return true
}

// findReassignments 查找指针重新赋值操作（修复递归过深问题）
func (d *UAFDetectorImproved) findReassignments(ctx *core.AnalysisContext, funcNode *sitter.Node) {
	// 使用visited map防止循环引用导致的栈溢出
	visited := make(map[uintptr]bool)

	// 遍历函数体，查找赋值表达式
	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		// 循环检测：避免重复处理同一节点
		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		// 查找赋值表达式
		if core.SafeType(node) == "assignment_expression" {
			left := core.SafeChildByFieldName(node, "left")
			right := core.SafeChildByFieldName(node, "right")

			if left != nil && core.SafeType(left) == "identifier" {
				varName := strings.TrimSpace(ctx.GetSourceText(left))

				// 检查右侧是否有 malloc（重新分配内存）
				if right != nil && d.hasMallocCall(ctx, right) {
					// 清除之前的释放状态
					if info, exists := d.freedPointers[varName]; exists {
						info.Reassigned = true
						info.IsValid = false // 重新分配后，之前的UAF不再有效
					}
				}
			}
		}

		// 递归处理子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	// 从函数体开始遍历
	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}
}

// findContentCopies 查找内容复制操作 (malloc + strcpy)（修复递归过深问题）
// 这避免了将"复制内容到新内存"误报为 UAF
func (d *UAFDetectorImproved) findContentCopies(ctx *core.AnalysisContext, funcNode *sitter.Node) {
	var copyPatterns [][]*sitter.Node

	// 使用visited map防止循环引用
	visited := make(map[uintptr]bool)

	// 遍历函数体
	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		// 循环检测
		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		// 查找 malloc -> strcpy 模式
		if core.SafeType(node) == "call_expression" {
			funcName := d.getFunctionName(ctx, node)
			if funcName == "malloc" || funcName == "calloc" {
				// 记录 malloc 调用
				varName := d.extractMallocTarget(ctx, node)
				if varName != "" {
					// 查找后续的 strcpy/memcpy 调用
					d.findStrcpyAfterMalloc(ctx, funcNode, node, varName, &copyPatterns)
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}

	// 处理找到的复制模式
	for _, pattern := range copyPatterns {
		if len(pattern) >= 2 {
			mallocCall := pattern[0]
			strcpyCall := pattern[1]

			// 提取目标变量名
			srcVar := d.extractMallocTarget(ctx, mallocCall)
			dstVar := d.extractStrcpyTarget(ctx, strcpyCall)

			if srcVar != "" && dstVar != "" && srcVar != dstVar {
				// 记录：srcVar 的内容被复制到 dstVar
				// 后续对 srcVar 的 free 不是对 dstVar 的 UAF
				d.copiesMade[srcVar] = dstVar
			}
		}
	}
}

// findStrcpyAfterMalloc 在 malloc 调用后查找 strcpy 调用
func (d *UAFDetectorImproved) findStrcpyAfterMalloc(ctx *core.AnalysisContext, funcNode *sitter.Node, mallocNode *sitter.Node, srcVar string, patterns *[][]*sitter.Node) {
	mallocLine := int(mallocNode.StartPoint().Row)

	// 查找同一作用域内的后续调用
	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		// 只检查 malloc 后的代码（在同一条语句或下几条）
		nodeLine := int(node.StartPoint().Row)
		if nodeLine <= mallocLine || nodeLine > mallocLine+5 {
			// 跳过 malloc 之前的代码和距离太远的代码
			for i := 0; i < int(core.SafeChildCount(node)); i++ {
				traverse(core.SafeChild(node, i))
			}
			return
		}

		// 查找 strcpy/ memcpy 调用
		if core.SafeType(node) == "call_expression" {
			funcName := d.getFunctionName(ctx, node)
			if funcName == "strcpy" || funcName == "memcpy" || funcName == "strncpy" {
				// 检查第一个参数是否是 malloc 返回的变量
				dstVar := d.extractStrcpyTarget(ctx, node)
				if dstVar == srcVar {
					// 找到复制模式
					*patterns = append(*patterns, []*sitter.Node{mallocNode, node})
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}
}

// findFreeCalls 查找 free 调用
func (d *UAFDetectorImproved) findFreeCalls(ctx *core.AnalysisContext, funcNode *sitter.Node) []*sitter.Node {
	var freeCalls []*sitter.Node

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		if core.SafeType(node) == "call_expression" {
			funcNode := core.SafeChildByFieldName(node, "function")
			if funcNode != nil && core.SafeType(funcNode) == "identifier" {
				funcName := strings.TrimSpace(ctx.GetSourceText(funcNode))
				if funcName == "free" || funcName == "ZFREE" {
					args := core.SafeChildByFieldName(node, "arguments")
					if args != nil && core.SafeChildCount(args) > 0 {
						freeCalls = append(freeCalls, node)
					}
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}

	return freeCalls
}

// findUsages 查找变量使用（修复递归过深问题）
func (d *UAFDetectorImproved) findUsages(ctx *core.AnalysisContext, funcNode *sitter.Node, vulns *[]core.DetectorVulnerability) {
	// 获取函数定义的范围
	funcStartLine := int(funcNode.StartPoint().Row)

	// 收集所有 free 调用的行号
	freeLines := make(map[string]int) // varName -> line
	for varName, info := range d.freedPointers {
		if info.IsValid {
			freeLines[varName] = info.FreeLine
		}
	}

	// 使用visited map防止循环引用导致的栈溢出
	visited := make(map[uintptr]bool)

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		// 循环检测：避免重复处理同一节点
		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		nodeLine := int(node.StartPoint().Row)

		// 检查是否为使用节点
		if d.isUsage(node) {
			varName := d.extractVariableName(ctx, node)
			if varName == "" {
				for i := 0; i < int(core.SafeChildCount(node)); i++ {
					traverse(core.SafeChild(node, i))
				}
				return
			}

			// 检查是否为 UAF
			if info, exists := d.freedPointers[varName]; exists && info.IsValid {
				// 检查使用是否在 free 之后
				isAfterFree := nodeLine > info.FreeLine

				// 应用误报过滤器（传递funcNode以支持CFG分析）
				if d.shouldReportUAF(ctx, funcNode, varName, node, nodeLine, funcStartLine, info, isAfterFree) {
					vuln := d.BaseDetector.CreateVulnerability(
						core.CWE416,
						fmt.Sprintf("Variable '%s' used after free (line %d freed, used at line %d)", varName, info.FreeLine+1, nodeLine+1),
						node,
						core.ConfidenceMedium,
						core.SeverityCritical,
					)
					*vulns = append(*vulns, vuln)
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	traverse(core.SafeChildByFieldName(funcNode, "body"))
}

// shouldReportUAF 判断是否应该报告 UAF（误报过滤）
// 核心改进：使用CFG进行路径可达性检查，只报告真正可达路径上的UAF
func (d *UAFDetectorImproved) shouldReportUAF(ctx *core.AnalysisContext, funcNode *sitter.Node, varName string, usageNode *sitter.Node, usageLine, funcStartLine int, info *FreedPointerInfo, isAfterFree bool) bool {
	// 过滤器1：使用必须在 free 之后
	if !isAfterFree {
		return false
	}

	// 过滤器2：如果指针被重新赋值，不是 UAF
	if info.Reassigned {
		return false
	}

	// 过滤器3：检查是否有内容复制（指针转移）
	if _, hasCopy := d.copiesMade[varName]; hasCopy {
		return false
	}

	// 过滤器3.5: 检查参数复制关系
	if d.isVarCopiedInCall(varName, funcStartLine) {
		return false
	}

	// *** 核心改进：CFG路径可达性检查 ***
	// 这是减少误报的关键：只报告在CFG中从free节点可达的usage
	cfg, hasCFG := d.functionCFGs[funcNode]
	if hasCFG && cfg != nil {
		// 在CFG中查找包含free调用的节点
		freeBlock := d.findBlockContainingLine(cfg, info.FreeLine)
		usageBlock := d.findBlockContainingLine(cfg, usageLine)

		if freeBlock != nil && usageBlock != nil {
			// 检查在CFG中是否真的存在从free到usage的路径
			// 如果不在同一条路径上，则不是UAF
			if !d.isPathReachableInCFG(freeBlock, usageBlock) {
				return false // 不同路径，不是UAF
			}
		}
	}

	// 过滤器4：检查是否是函数参数（可能由调用者管理）
	if d.isFunctionParameter(ctx, varName, funcStartLine) {
		return true
	}

	// 过滤器5：检查是否是结构体成员
	if strings.Contains(varName, "->") || strings.Contains(varName, ".") {
		return true
	}

	// 过滤器6：检查使用点和 free 点之间的距离
	distance := usageLine - info.FreeLine
	if distance > 100 {
		return false
	}

	// 过滤器7：检查是否有明显的保护机制
	if d.hasGuardClause(ctx, usageNode, varName) {
		return false
	}

	return true
}

// findBlockContainingLine 在CFG中查找包含指定行号的块
func (d *UAFDetectorImproved) findBlockContainingLine(cfg *core.CFG, line int) *core.CFGNode {
	for _, block := range cfg.Nodes {
		for _, stmt := range block.Statements {
			if stmt != nil {
				stmtLine := int(stmt.StartPoint().Row)
				if stmtLine == line {
					return block
				}
			}
		}
	}
	return nil
}

// checkEarlyReturnAfterFree 检查 free 后是否有提前返回（导致后续代码不可达）
// 这是减少误报的关键：free 在错误处理分支 + return → 后续代码不会执行
func (d *UAFDetectorImproved) checkEarlyReturnAfterFree(ctx *core.AnalysisContext, funcNode *sitter.Node, freeLine, usageLine int) bool {
	// 查找 free 和 usage 之间的控制流语句
	// 关键模式：if (error) { free(x); return; } ... usage(x)

	visited := make(map[uintptr]bool)
	var earlyReturnLine int = -1

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		nodeType := core.SafeType(node)
		nodeLine := int(node.StartPoint().Row)

		// 检查是否在 free 和 usage 之间
		if nodeLine > freeLine && nodeLine < usageLine {
			// 检测 return 语句
			if nodeType == "return_statement" {
				earlyReturnLine = nodeLine
				return
			}

			// 检测 if 语句中包含 return 的模式
			if nodeType == "if_statement" {
				// 检查 if 分支是否包含 free + return
				consequence := core.SafeChild(node, 2) // if 分支
				if consequence != nil && d.hasFreeAndReturnPattern(ctx, consequence, freeLine) {
					// 找到了 free + return 模式
					earlyReturnLine = nodeLine
					return
				}
			}
		}

		// 递归遍历子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}

	// 如果在 free 和 usage 之间发现了 return，说明路径不可达
	return earlyReturnLine != -1 && earlyReturnLine < usageLine
}

// hasFreeAndReturnPattern 检查代码块是否包含 free + return 模式
func (d *UAFDetectorImproved) hasFreeAndReturnPattern(ctx *core.AnalysisContext, block *sitter.Node, freeLine int) bool {
	visited := make(map[uintptr]bool)
	foundFree := false

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		nodeType := core.SafeType(node)
		nodeLine := int(node.StartPoint().Row)

		// 检查是否为 free 调用
		if !foundFree && nodeType == "call_expression" {
			funcName := d.getFunctionName(ctx, node)
			if funcName == "free" && nodeLine == freeLine {
				foundFree = true
			}
		}

		// 在 free 之后检查 return
		if foundFree && nodeType == "return_statement" {
			return // 找到了 free + return 模式
		}

		// 递归遍历子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	traverse(block)
	return foundFree
}

// isPathReachableInCFG 检查在CFG中是否存在从freeBlock到usageBlock的路径
// *** 改进版本：结合提前返回检测 ***
func (d *UAFDetectorImproved) isPathReachableInCFG(freeBlock, usageBlock *core.CFGNode) bool {
	if freeBlock == nil || usageBlock == nil {
		return true // 保守：如果找不到块，假设可达
	}

	// 如果是同一个块，检查行序
	if freeBlock.ID == usageBlock.ID {
		return true
	}

	// *** 新增：检查是否有提前返回 ***
	// 如果 free 块以 return 结束，则不会到达 usage 块
	if d.blockEndsWithReturn(freeBlock) {
		return false
	}

	// BFS搜索从freeBlock可达的所有节点
	visited := make(map[int]bool)
	queue := []*core.CFGNode{freeBlock}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.ID] {
			continue
		}
		visited[current.ID] = true

		// 找到目标节点
		if current.ID == usageBlock.ID {
			return true
		}

		// 添加后继节点
		for _, succ := range current.Successors {
			if !visited[succ.ID] {
				queue = append(queue, succ)
			}
		}
	}

	return false // 没有路径可达
}

// blockEndsWithReturn 检查 CFG 块是否以 return 语句结束
func (d *UAFDetectorImproved) blockEndsWithReturn(block *core.CFGNode) bool {
	if block == nil || len(block.Statements) == 0 {
		return false
	}

	// 检查最后一个语句是否为 return
	lastStmt := block.Statements[len(block.Statements)-1]
	if lastStmt != nil && core.SafeType(lastStmt) == "return_statement" {
		return true
	}

	return false
}

// isFunctionParameter 检查变量是否为函数参数
func (d *UAFDetectorImproved) isFunctionParameter(ctx *core.AnalysisContext, varName string, funcStartLine int) bool {
	// 查找函数参数列表
	params, _ := ctx.QueryNodes("(parameter_declaration) @param")
	if len(params) == 0 {
		return false
	}

	// 检查变量名是否在参数列表中
	for _, paramDecl := range params {
		var traverse func(node *sitter.Node) bool
		traverse = func(node *sitter.Node) bool {
			if core.SafeType(node) == "identifier" {
				name := strings.TrimSpace(ctx.GetSourceText(node))
				if name == varName {
					return true
				}
			}
			for i := 0; i < int(core.SafeChildCount(node)); i++ {
				if traverse(core.SafeChild(node, i)) {
					return true
				}
			}
			return false
		}
		if traverse(paramDecl) {
			return true
		}
	}

	return false
}

// hasGuardClause 检查是否有保护性子句
func (d *UAFDetectorImproved) hasGuardClause(ctx *core.AnalysisContext, node *sitter.Node, varName string) bool {
	// 查找父级 if 语句
	parent := node.Parent()
	for parent != nil {
		if core.SafeType(parent) == "if_statement" || core.SafeType(parent) == "conditional_expression" {
			// 检查条件是否检查指针是否为 NULL
			condition := core.SafeChildByFieldName(parent, "condition")
			if condition != nil {
				conditionStr := ctx.GetSourceText(condition)
				if strings.Contains(conditionStr, varName) &&
				   (strings.Contains(conditionStr, "!=") || strings.Contains(conditionStr, "==")) {
					return true
				}
			}
		}
		parent = parent.Parent()
	}
	return false
}

// hasMallocCall 检查节点或其子节点是否包含 malloc 调用
func (d *UAFDetectorImproved) hasMallocCall(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	if core.SafeType(node) == "call_expression" {
		funcName := d.getFunctionName(ctx, node)
		if funcName == "malloc" || funcName == "calloc" || funcName == "realloc" {
			return true
		}
	}

	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		if d.hasMallocCall(ctx, core.SafeChild(node, i)) {
			return true
		}
	}

	return false
}

// extractMallocTarget 提取 malloc 调用的目标变量
func (d *UAFDetectorImproved) extractMallocTarget(ctx *core.AnalysisContext, mallocCall *sitter.Node) string {
	// 查找赋值表达式的左侧
	parent := mallocCall.Parent()
	if parent != nil && core.SafeType(parent) == "assignment_expression" {
		left := core.SafeChildByFieldName(parent, "left")
		if left != nil && core.SafeType(left) == "identifier" {
			return strings.TrimSpace(ctx.GetSourceText(left))
		}
	}
	return ""
}

// extractStrcpyTarget 提取 strcpy 调用的目标变量
func (d *UAFDetectorImproved) extractStrcpyTarget(ctx *core.AnalysisContext, strcpyCall *sitter.Node) string {
	args := core.SafeChildByFieldName(strcpyCall, "arguments")
	if args == nil || core.SafeChildCount(args) < 1 {
		return ""
	}

	// 第一个参数是目标
	firstArg := core.SafeChild(args, 0)
	if firstArg != nil {
		return d.extractIdentifierFromExpr(ctx, firstArg)
	}

	return ""
}

// extractIdentifierFromExpr 从表达式中提取标识符
func (d *UAFDetectorImproved) extractIdentifierFromExpr(ctx *core.AnalysisContext, expr *sitter.Node) string {
	if expr == nil {
		return ""
	}

	if core.SafeType(expr) == "identifier" {
		return strings.TrimSpace(ctx.GetSourceText(expr))
	}

	if core.SafeType(expr) == "pointer_expression" {
		// 指针解引用：expr -> *ptr
		arg := core.SafeChild(expr, 0)
		if arg != nil {
			return d.extractIdentifierFromExpr(ctx, arg)
		}
	}

	return ""
}

// getFunctionName 获取函数调用中的函数名
func (d *UAFDetectorImproved) getFunctionName(ctx *core.AnalysisContext, node *sitter.Node) string {
	funcNode := core.SafeChildByFieldName(node, "function")
	if funcNode == nil {
		return ""
	}

	if core.SafeType(funcNode) == "identifier" {
		return strings.TrimSpace(ctx.GetSourceText(funcNode))
	}

	// 处理指针解引用的情况（如 (*ptr)()）
	if core.SafeType(funcNode) == "pointer_expression" {
		ptr := core.SafeChild(funcNode, 0)
		if ptr != nil && core.SafeType(ptr) == "identifier" {
			return strings.TrimSpace(ctx.GetSourceText(ptr))
		}
	}

	return ""
}

// isUsage 检查节点是否为使用
func (d *UAFDetectorImproved) isUsage(node *sitter.Node) bool {
	nodeType := core.SafeType(node)
	return nodeType == "pointer_expression" ||
		nodeType == "call_expression" ||
		nodeType == "field_expression"  // *** 新增：field_expression 也是使用（如 ptr->member）***
	// 注意：assignment_expression 不是使用，而是赋值（如 ptr = NULL）
}

// extractVariableName 提取变量名
// *** 修改：对于 field_expression，返回完整路径而不是简单标识符 ***
func (d *UAFDetectorImproved) extractVariableName(ctx *core.AnalysisContext, node *sitter.Node) string {
	// 首先检查是否是 field_expression，如果是则返回完整路径
	nodeType := core.SafeType(node)
	if nodeType == "field_expression" {
		fullPath, _ := d.getFullAccessPath(ctx, node)
		if fullPath != "" {
			return fullPath
		}
	}

	// 对于其他类型，查找标识符
	var identifier *sitter.Node
	d.findIdentifier(node, &identifier)

	if identifier != nil {
		return strings.TrimSpace(ctx.GetSourceText(identifier))
	}
	return ""
}

// findIdentifier 查找标识符节点
func (d *UAFDetectorImproved) findIdentifier(node *sitter.Node, identifier **sitter.Node) {
	if node == nil {
		return
	}

	if core.SafeType(node) == "identifier" {
		*identifier = node
		return
	}

	// 优先查找直接子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.findIdentifier(core.SafeChild(node, i), identifier)
		if *identifier != nil {
			return
		}
	}
}

// getFreedVariable 获取被释放的变量
// *** 修改：返回完整的参数表达式，而不是只返回标识符 ***
func (d *UAFDetectorImproved) getFreedVariable(ctx *core.AnalysisContext, freeCall *sitter.Node) *sitter.Node {
	args := core.SafeChildByFieldName(freeCall, "arguments")
	if args == nil || core.SafeChildCount(args) == 0 {
		return nil
	}

	// 提取第一个实际参数（跳过标点符号）
	firstArg := d.extractFirstArgument(args)
	if firstArg == nil {
		return nil
	}

	// *** 直接返回完整的参数表达式，而不是只提取标识符 ***
	// 这样后续可以提取完整的成员访问路径
	return firstArg
}

// *** 新增：提取完整的成员访问路径 ***
// getFullAccessPath 提取完整的成员访问路径
// 例如：从 "zi->ci.central_header" 返回 "zi->ci.central_header"
// 从 "zi" 返回 "zi"
func (d *UAFDetectorImproved) getFullAccessPath(ctx *core.AnalysisContext, node *sitter.Node) (string, bool) {
	if node == nil {
		return "", false
	}

	nodeType := core.SafeType(node)

	// 标识符：直接返回
	if nodeType == "identifier" {
		return ctx.GetSourceText(node), false
	}

	// field_expression: ptr->member 或 ptr.member
	if nodeType == "field_expression" {
		// 递归构建完整路径
		object := core.SafeChildByFieldName(node, "object")
		field := core.SafeChildByFieldName(node, "field")

		basePath, _ := d.getFullAccessPath(ctx, object)
		fieldName := ""
		if field != nil {
			fieldName = ctx.GetSourceText(field)
		}

		// 判断是 -> 还是 .
		op := "->"
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			childType := core.SafeType(child)
			if childType == "." {
				op = "."
				break
			}
		}

		fullPath := basePath + op + fieldName
		return fullPath, true // true表示这是一个结构体成员访问
	}

	// pointer_expression: *ptr
	if nodeType == "pointer_expression" {
		operand := core.SafeChildByFieldName(node, "operand")
		return d.getFullAccessPath(ctx, operand)
	}

	// subscript_expression: arr[index]
	if nodeType == "subscript_expression" {
		object := core.SafeChild(node, 0)
		return d.getFullAccessPath(ctx, object)
	}

	return "", false
}

// extractFirstArgument 提取第一个实际参数（跳过标点符号）
func (d *UAFDetectorImproved) extractFirstArgument(args *sitter.Node) *sitter.Node {
	if core.SafeType(args) == "argument_list" {
		// 查找第一个非标点符号的参数
		for i := 0; i < int(core.SafeChildCount(args)); i++ {
			child := core.SafeChild(args, i)
			childType := core.SafeType(child)

			// 跳过标点符号
			if childType == "," || childType == "(" || childType == ")" {
				continue
			}

			return child
		}
	}
	return nil
}

// isVarCopiedInCall 检查变量是否在调用函数时被复制
// 针对 gzlib.c: path 被传给 gz_open 并复制
func (d *UAFDetectorImproved) isVarCopiedInCall(varName string, funcStartLine int) bool {
	// 遍历所有参数复制记录
	for _, info := range d.paramCopies {
		if info.ParamName == varName && info.CopyMade {
			// 找到匹配：变量作为参数传递给函数并在函数内被复制
			// 这意味着原始指针被释放后，副本仍然存在
			return true
		}
	}
	return false
}

// ============================================================================
// 指针空值化追踪
// ============================================================================

// findNullificationOperations 检测指针空值化操作 (ptr = NULL)
// 如果指针在free后立即被设置为NULL，这表明内存已被安全化
func (d *UAFDetectorImproved) findNullificationOperations(ctx *core.AnalysisContext, funcNode *sitter.Node, freedPointers map[string]*FreedPointerInfo) {
	visited := make(map[uintptr]bool)

	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeID := node.ID()
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		nodeType := core.SafeType(node)
		nodeLine := int(node.StartPoint().Row)

		// 检查赋值表达式
		if nodeType == "assignment_expression" {
			left := core.SafeChildByFieldName(node, "left")
			right := core.SafeChildByFieldName(node, "right")

			if left != nil && right != nil {
				// 检查右侧是否是NULL/0
				if d.isNullExpression(ctx, right) {
					// 提取左侧的变量路径
					leftPath, _ := d.getFullAccessPath(ctx, left)

					// 检查这个指针是否在我们的freedPointers列表中
					for varName, info := range freedPointers {
						if !info.IsValid {
							continue
						}

						// 检查是否是精确路径匹配
						if leftPath == varName {
							// 确认空值化操作发生在free之后（允许几行的间隔，例如if语句）
							if nodeLine >= info.FreeLine && nodeLine <= info.FreeLine+10 {
								info.Nullified = true
								info.NullifiedLine = nodeLine
								info.IsValid = false // 标记为无效，因为指针已被安全化
							}
						}
					}
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	traverse(core.SafeChildByFieldName(funcNode, "body"))
}

// isNullExpression 检查表达式是否是NULL/0
func (d *UAFDetectorImproved) isNullExpression(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	nodeType := core.SafeType(node)
	text := strings.TrimSpace(ctx.GetSourceText(node))

	// 检查NULL、0、nullptr等
	switch nodeType {
	case "identifier":
		return text == "NULL" || text == "nullptr"
	case "number_literal":
		return text == "0"
	case "null":
		return true
	}

	// 检查cast表达式：(void *)0 或 (char *)NULL
	if nodeType == "cast_expression" {
		// 检查类型和值
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if d.isNullExpression(ctx, child) {
				return true
			}
		}
	}

	return false
}
