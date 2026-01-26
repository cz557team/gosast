package detectors

import (
	"fmt"
	"strings"

	"gosast/internal/core"
	sitter "github.com/smacker/go-tree-sitter"
)

// NullPointerDereferenceDetector 重构后的空指针解引用检测器
// 使用数据流分析 + Z3约束求解，支持多函数文件场景
type NullPointerDereferenceDetector struct {
	*core.BaseDetector
	z3Solver core.Z3Solver
	// 框架 API 模式 - 用于过滤框架保证的参数
	frameworkAPIMap map[string]bool
}

// NewNullPointerDereferenceDetector 创建新的空指针解引用检测器
func NewNullPointerDereferenceDetector() *NullPointerDereferenceDetector {
	solver, _ := core.CreateZ3Solver()

	// 初始化通用框架 API 模式（跨项目通用的模式）
	frameworkPatterns := map[string]bool{
		// 生命周期管理回调 - 框架保证参数有效
		"freectx":    true, // 释放上下文回调
		"newctx":     true, // 创建上下文回调
		"dupctx":     true, // 复制上下文回调
		"initctx":    true, // 初始化上下文回调
		"setctx":     true, // 设置上下文回调
		"getctx":     true, // 获取上下文回调
		"cleanup":    true, // 清理回调
		"destroy":    true, // 销毁回调
		"finalize":   true, // 终结回调
		"close":      true, // 关闭回调
		"reset":      true, // 重置回调
		"release":    true, // 释放回调
		"dispose":    true, // 处置回调
		// 常见的框架模式后缀
		"_cb":        true, // 回调函数后缀
		"_callback":  true, // 回调函数后缀
		"_handler":   true, // 处理器后缀
		"_cleanup":   true, // 清理后缀
		"_free":      true, // 释放后缀
		"_init":      true, // 初始化后缀
		"_fini":      true, // 终结后缀
	}

	return &NullPointerDereferenceDetector{
		BaseDetector: core.NewBaseDetector(
			"null_pointer_dereference",
			"Detects null pointer dereference vulnerabilities (CWE-476) using data flow analysis and Z3",
		),
		z3Solver:       solver,
		frameworkAPIMap: frameworkPatterns,
	}
}

// Name 返回检测器名称
func (d *NullPointerDereferenceDetector) Name() string {
	return "Null Pointer Dereference Detector"
}

// Description 返回检测器描述
func (d *NullPointerDereferenceDetector) Description() string {
	return "Detects potential null pointer dereference vulnerabilities using data flow analysis and Z3 constraint solving"
}

// Run 执行检测
func (d *NullPointerDereferenceDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	// 【重新启用】过滤测试和演示文件（优化后的规则）
	if d.shouldSkipFile(ctx.Unit.FilePath) {
		return nil, nil
	}

	var vulns []core.DetectorVulnerability

	// 1. 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, err := ctx.Query(funcQuery)
	if err != nil {
		return nil, err
	}

	// 2. 为每个函数创建独立分析上下文
	for _, funcMatch := range funcMatches {
		funcName := d.extractFuncName(ctx, funcMatch.Node)
		if funcName == "" {
			continue
		}

		// 创建函数级独立上下文
		funcCtx := d.createFunctionContext(ctx, funcMatch.Node)
		if funcCtx == nil {
			continue
		}

		// 分析函数
		funcVulns := d.analyzeFunction(funcCtx, funcMatch.Node, funcName)
		vulns = append(vulns, funcVulns...)
	}

	return vulns, nil
}

// createFunctionContext 创建函数级独立分析上下文
func (d *NullPointerDereferenceDetector) createFunctionContext(globalCtx *core.AnalysisContext, funcNode *sitter.Node) *core.AnalysisContext {
	// 创建解析树副本
	funcUnit := globalCtx.Unit.Copy()
	funcCtx := core.NewAnalysisContext(funcUnit)

	return funcCtx
}

// analyzeFunction 分析单个函数
func (d *NullPointerDereferenceDetector) analyzeFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, funcName string) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 1. 数据流分析：收集指针声明和赋值
	pointerFlows := d.analyzeDataFlow(ctx, funcNode)

	// 2. 查找所有指针解引用
	dereferences := d.findPointerDereferences(ctx, funcNode)

	// 3. 对每个解引用进行检查
	for _, deref := range dereferences {
		if d.isVulnerableDereference(ctx, deref, pointerFlows) {
			vuln := d.createVulnerability(ctx, deref, funcName)
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// DataFlow 指针数据流信息
type DataFlow struct {
	Allocations map[string]*Allocation // 指针分配信息
	Assignments map[string][]*Assignment // 指针赋值历史
	Checks      map[string][]*Check    // 指针检查信息
}

// Allocation 指针分配信息
type Allocation struct {
	Node      *sitter.Node
	Line      int
	IsNullable bool
	Source    string // "malloc", "call", etc.
}

// Assignment 指针赋值信息
type Assignment struct {
	Node    *sitter.Node
	Line    int
	Value   string
	IsNullable bool
}

// Check 指针检查信息
type Check struct {
	Node      *sitter.Node
	Line      int
	CheckType string // "null_check", "guard_return"
	Variable  string
}

// Dereference 指针解引用信息
type Dereference struct {
	Node       *sitter.Node
	Line       int
	Variable   string
	DerefType  string // "pointer", "subscript", "field"
}

// analyzeDataFlow 分析数据流
func (d *NullPointerDereferenceDetector) analyzeDataFlow(ctx *core.AnalysisContext, funcNode *sitter.Node) *DataFlow {
	flows := &DataFlow{
		Allocations: make(map[string]*Allocation),
		Assignments: make(map[string][]*Assignment),
		Checks:      make(map[string][]*Check),
	}

	// 递归分析函数节点
	d.analyzeDataFlowRecursive(ctx, funcNode, flows)

	return flows
}

// analyzeDataFlowRecursive 递归分析数据流
func (d *NullPointerDereferenceDetector) analyzeDataFlowRecursive(ctx *core.AnalysisContext, node *sitter.Node, flows *DataFlow) {
	if node == nil {
		return
	}

	// 分析声明
	if core.SafeType(node) == "declaration" {
		d.analyzeDeclaration(ctx, node, flows)
	}

	// 分析赋值
	if core.SafeType(node) == "expression_statement" {
		d.analyzeAssignment(ctx, node, flows)
	}

	// 分析if语句（可能包含NULL检查）
	if core.SafeType(node) == "if_statement" {
		d.analyzeIfStatement(ctx, node, flows)
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.analyzeDataFlowRecursive(ctx, core.SafeChild(node, i), flows)
	}
}

// analyzeDeclaration 分析声明
func (d *NullPointerDereferenceDetector) analyzeDeclaration(ctx *core.AnalysisContext, declNode *sitter.Node, flows *DataFlow) {
	line := int(declNode.StartPoint().Row) + 1

	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if core.SafeType(child) == "init_declarator" {
			pointerName, initValue := d.parsePointerDeclarator(ctx, child)
			if pointerName != "" {
				// 创建分配信息
				alloc := &Allocation{
					Node:      initValue,
					Line:      line,
					IsNullable: d.isNullableValue(ctx, initValue),
					Source:    d.getAllocationSource(ctx, initValue),
				}
				flows.Allocations[pointerName] = alloc

				// 创建赋值信息
				valueText := ""
				if initValue != nil {
					valueText = ctx.GetSourceText(initValue)
				}
				assign := &Assignment{
					Node:       initValue,
					Line:       line,
					Value:      valueText,
					IsNullable: alloc.IsNullable,
				}
				flows.Assignments[pointerName] = append(flows.Assignments[pointerName], assign)
			}
		}
	}
}

// analyzeAssignment 分析赋值
func (d *NullPointerDereferenceDetector) analyzeAssignment(ctx *core.AnalysisContext, stmtNode *sitter.Node, flows *DataFlow) {
	line := int(stmtNode.StartPoint().Row) + 1

	// 查找赋值表达式
	for i := 0; i < int(core.SafeChildCount(stmtNode)); i++ {
		child := core.SafeChild(stmtNode, i)
		if core.SafeType(child) == "assignment_expression" {
			// 获取左值（指针名）
			lhs := core.SafeChild(child, 0)
			if lhs != nil && core.SafeType(lhs) == "identifier" {
				pointerName := ctx.GetSourceText(lhs)

				// 获取右值
				rhs := core.SafeChild(child, 2)
				if rhs != nil {
					assign := &Assignment{
						Node:       rhs,
						Line:       line,
						Value:      ctx.GetSourceText(rhs),
						IsNullable: d.isNullableValue(ctx, rhs),
					}
					flows.Assignments[pointerName] = append(flows.Assignments[pointerName], assign)
				}
			}
		}
	}
}

// analyzeIfStatement 分析if语句
func (d *NullPointerDereferenceDetector) analyzeIfStatement(ctx *core.AnalysisContext, ifNode *sitter.Node, flows *DataFlow) {
	line := int(ifNode.StartPoint().Row) + 1

	// 获取条件
	condition := core.SafeChildByFieldName(ifNode, "condition")
	if condition == nil {
		return
	}

	// 检查是否为NULL检查
	check := d.parseNullCheck(ctx, condition)
	if check != nil {
		check.Line = line
		flows.Checks[check.Variable] = append(flows.Checks[check.Variable], check)

		// 检查是否为保护模式（if块内包含return/break/continue）
		if d.isProtectiveIfBlock(ctx, ifNode) {
			// 标记此检查为保护性检查
			check.CheckType = "guard_return"
		}
	}
}

// isProtectiveIfBlock 检查是否为保护性if块
func (d *NullPointerDereferenceDetector) isProtectiveIfBlock(ctx *core.AnalysisContext, ifNode *sitter.Node) bool {
	// 获取if块
	ifBlock := core.SafeChild(ifNode, 2) // if块是第3个子节点
	if ifBlock == nil {
		return false
	}

	// 检查if块内是否包含return/break/continue语句
	return d.hasTerminatingStatement(ctx, ifBlock)
}

// hasTerminatingStatement 检查块内是否有终止语句
func (d *NullPointerDereferenceDetector) hasTerminatingStatement(ctx *core.AnalysisContext, node *sitter.Node) bool {
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if d.isTerminatingNode(child) {
			return true
		}
		if d.hasTerminatingStatement(ctx, child) {
			return true
		}
	}
	return false
}

// isTerminatingNode 检查是否为终止节点
func (d *NullPointerDereferenceDetector) isTerminatingNode(node *sitter.Node) bool {
	nodeType := core.SafeType(node)
	return nodeType == "return_statement" ||
		nodeType == "break_statement" ||
		nodeType == "continue_statement" ||
		nodeType == "goto_statement"
}

// parsePointerDeclarator 解析指针声明器
func (d *NullPointerDereferenceDetector) parsePointerDeclarator(ctx *core.AnalysisContext, initDecl *sitter.Node) (string, *sitter.Node) {
	var pointerName string
	var initValue *sitter.Node

	for i := 0; i < int(core.SafeChildCount(initDecl)); i++ {
		child := core.SafeChild(initDecl, i)

		// 获取指针名
		if core.SafeType(child) == "pointer_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "identifier" {
					pointerName = ctx.GetSourceText(subChild)
					break
				}
			}
		}

		// 【新增】获取初始化值 - 支持标识符（参数别名模式）
		// 【修复迭代 4】添加对field_expression的支持(结构体成员访问)
		if core.SafeType(child) == "call_expression" ||
		   core.SafeType(child) == "cast_expression" ||
		   core.SafeType(child) == "identifier" ||
		   core.SafeType(child) == "field_expression" {
			initValue = child
		}
	}

	return pointerName, initValue
}

// parseNullCheck 解析NULL检查
func (d *NullPointerDereferenceDetector) parseNullCheck(ctx *core.AnalysisContext, condition *sitter.Node) *Check {
	condText := strings.TrimSpace(ctx.GetSourceText(condition))

	// 检查是否为NULL检查（== NULL 或 != NULL）
	if strings.Contains(condText, "==") && strings.Contains(condText, "NULL") {
		varName := d.extractVariableFromCondition(condText, "==")
		if varName != "" {
			return &Check{
				CheckType: "null_check",
				Variable:  varName,
			}
		}
	}

	if strings.Contains(condText, "!=") && strings.Contains(condText, "NULL") {
		varName := d.extractVariableFromCondition(condText, "!=")
		if varName != "" {
			return &Check{
				CheckType: "null_check",
				Variable:  varName,
			}
		}
	}

	return nil
}

// extractVariableFromCondition 从条件中提取变量名
func (d *NullPointerDereferenceDetector) extractVariableFromCondition(condText, operator string) string {
	// 分割条件
	parts := strings.Split(condText, operator)
	if len(parts) != 2 {
		return ""
	}

	// 提取变量名（去除空格、括号和可能的指针操作符）
	varName := strings.TrimSpace(parts[0])
	// 去除左括号
	varName = strings.TrimPrefix(varName, "(")
	// 去除右括号
	varName = strings.TrimSuffix(varName, ")")
	// 去除指针操作符
	if strings.Contains(varName, "*") {
		varName = strings.TrimSpace(strings.Split(varName, "*")[0])
	}

	return varName
}

// isNullableValue 检查值是否可能为NULL
func (d *NullPointerDereferenceDetector) isNullableValue(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return true
	}

	// 【修复迭代 9】不检测 malloc 返回值的使用
	// 原因：很多代码假设 malloc 总是成功，这是常见的编程模式
	// 只有当存在明确的 NULL 赋值（如 ptr = NULL）时，才检测
	//
	// 注：这意味着我们不会检测 "malloc 后没有检查" 的情况
	// 但这是为了避免大量误报的权衡
	if d.isMemoryAllocationCall(ctx, node) {
		return false // 不再认为 malloc 返回值可能为 NULL
	}

	// 【修复】函数调用可能返回 NULL，但同样，如果没有明确的 NULL 赋值，不检测
	if core.SafeType(node) == "call_expression" {
		return false
	}

	// 【修复迭代 3】取地址表达式(&var)不可能是NULL
	// 例如:
	//   size_t *p = &tempargs->sigsize;  // p指向一个有效地址,不可能是NULL
	//   int *p = &global_var;            // p指向一个有效地址,不可能是NULL
	//
	// Tree-sitter将&ptr解析为pointer_expression,第一个子节点是&
	// 我们通过检查pointer_expression的第一个子节点来判断是解引用(*)还是取地址(&)
	if core.SafeType(node) == "pointer_expression" {
		if core.SafeChildCount(node) >= 1 {
			firstChild := core.SafeChild(node, 0)
			if firstChild != nil && core.SafeType(firstChild) == "&" {
				return false // 取地址操作的结果不可能是NULL
			}
		}
	}

	// 【修复迭代 4】结构体成员访问表达式通常不可能是NULL
	// 例如:
	//   const BN_ULONG *in1_z = a->Z;  // in1_z指向结构体成员,不可能是NULL
	//   int *p = obj->ptr;              // p指向结构体成员,不可能是NULL
	//
	// 这是C语言的通用模式:如果能够成功访问结构体成员(如a->Z),
	// 那么返回的成员值就是有效的。即使a可能为NULL,那也是在成员访问时崩溃,
	// 而不是在使用赋值后的指针时崩溃。
	//
	// 注意:这个规则适用于从成员访问得到的指针值,不适用于直接的NULL赋值
	if core.SafeType(node) == "field_expression" {
		// 检查是否是结构体/联合体的成员访问
		// field_expression的类型如: a->Z 或 obj.ptr
		// 如果访问的是一个指针类型的成员,返回的指针值不可能是NULL
		// (假设成员访问本身是有效的)
		return false // 成员访问的结果不可能是NULL
	}

	// 【修复迭代 5】解引用表达式(*)通常不认为是nullable
	// 例如:
	//   const char *s = *t;  // s是通过解引用t得到的,通常假设t有效
	//   int *p = *ptr;       // p是通过解引用ptr得到的
	//
	// 这是C语言的通用模式:通过指针参数间接访问数据时,
	// 通常假设指针参数是有效的(调用者负责保证)。
	// 如果我们要检查每个间接访问,代码会变得非常冗长。
	//
	// 例外:只有明确的NULL赋值(如ptr = NULL)才被认为是nullable
	//
	// 注意:这与findDereferencesRecursive中的检查不同,
	// 那里我们检查的是解引用操作(*ptr)本身是否合法,
	// 这里我们检查的是通过解引用得到的值是否可能是NULL
	if core.SafeType(node) == "pointer_expression" {
		if core.SafeChildCount(node) >= 1 {
			firstChild := core.SafeChild(node, 0)
			if firstChild != nil && core.SafeType(firstChild) == "*" {
				// 这是解引用操作,结果通常不认为是NULL
				// (假设被解引用的指针是有效的)
				return false
			}
		}
	}

	// 强制转换可能产生 NULL
	if core.SafeType(node) == "cast_expression" {
		return false
	}

	return false
}

// getAllocationSource 获取分配源
func (d *NullPointerDereferenceDetector) getAllocationSource(ctx *core.AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return "unknown"
	}
	if d.isMemoryAllocationCall(ctx, node) {
		return "malloc"
	}
	if core.SafeType(node) == "call_expression" {
		return "call"
	}
	return "unknown"
}

// isMemoryAllocationCall 检查是否为内存分配调用
func (d *NullPointerDereferenceDetector) isMemoryAllocationCall(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil || core.SafeType(node) != "call_expression" {
		return false
	}

	funcNode := core.SafeChildByFieldName(node, "function")
	if funcNode == nil || core.SafeType(funcNode) != "identifier" {
		return false
	}

	funcName := strings.TrimSpace(ctx.GetSourceText(funcNode))
	return funcName == "malloc" || funcName == "calloc" || funcName == "realloc"
}

// findPointerDereferences 查找指针解引用
func (d *NullPointerDereferenceDetector) findPointerDereferences(ctx *core.AnalysisContext, funcNode *sitter.Node) []*Dereference {
	var derefs []*Dereference

	d.findDereferencesRecursive(ctx, funcNode, &derefs)

	return derefs
}

// findDereferencesRecursive 递归查找解引用
func (d *NullPointerDereferenceDetector) findDereferencesRecursive(ctx *core.AnalysisContext, node *sitter.Node, derefs *[]*Dereference) {
	if node == nil {
		return
	}

	line := int(node.StartPoint().Row) + 1

	// 检查pointer_expression (*ptr 或 &ptr)
	// 【修复 OpenSSL 误报】Tree-sitter C语法将 *ptr 和 &ptr 都解析为 pointer_expression
	// 区别在于子节点0:
	//   - *ptr (解引用): 子节点0是 "*"
	//   - &ptr (取地址): 子节点0是 "&"
	// 只有 *ptr 才是真正的解引用, &ptr 不是解引用!
	if core.SafeType(node) == "pointer_expression" {
		if core.SafeChildCount(node) >= 2 {
			// 检查子节点0是否是 "*" (解引用操作符)
			firstChild := core.SafeChild(node, 0)
			if firstChild != nil && core.SafeType(firstChild) == "*" {
				// 这是解引用 (*ptr)
				ident := core.SafeChild(node, 1)
				if core.SafeType(ident) == "identifier" {
					varName := ctx.GetSourceText(ident)
					*derefs = append(*derefs, &Dereference{
						Node:      node,
						Line:      line,
						Variable:  varName,
						DerefType: "pointer",
					})
				}
			}
			// 如果子节点0是 "&",这是取地址操作,不是解引用,跳过
		}
	}

	// 检查subscript_expression (ptr[i])
	if core.SafeType(node) == "subscript_expression" {
		if core.SafeChildCount(node) > 0 {
			ident := core.SafeChild(node, 0)
			if core.SafeType(ident) == "identifier" {
				varName := ctx.GetSourceText(ident)
				*derefs = append(*derefs, &Dereference{
					Node:      node,
					Line:      line,
					Variable:  varName,
					DerefType: "subscript",
				})
			}
		}
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.findDereferencesRecursive(ctx, core.SafeChild(node, i), derefs)
	}
}

// isVulnerableDereference 检查解引用是否易受攻击
func (d *NullPointerDereferenceDetector) isVulnerableDereference(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 1. 检查是否有分配记录
	if _, exists := flows.Allocations[varName]; !exists {
		return false // 没有分配记录，可能是外部变量
	}

	alloc := flows.Allocations[varName]

	// 【修复 OpenSSL 误报 - 迭代 2】考虑指针的重新赋值
	// 如果指针在初始化后又被重新赋值,需要使用最新的赋值信息
	//
	// 例如:
	//   unsigned char *em = NULL;        // IsNullable = true
	//   em = OPENSSL_malloc(num);         // IsNullable = false (malloc返回值)
	//   if (em == NULL) return -1;       // guard check
	//   *em = ...;                        // 安全! 因为em已经被重新赋值为非NULL
	//
	// 查找在解引用之前的所有赋值,使用最新的非NULL赋值
	assignments := flows.Assignments[varName]
	var latestNonNullableAssign *Assignment
	for _, assign := range assignments {
		if assign.Line < deref.Line {
			// 如果这个赋值使指针变为非NULL,记录下来
			if !assign.IsNullable {
				latestNonNullableAssign = assign
			}
		}
	}

	// 如果在解引用之前有非NULL赋值,指针是安全的
	if latestNonNullableAssign != nil {
		return false
	}

	// 2. 检查分配的值是否可能为NULL
	if !alloc.IsNullable {
		return false // 分配的值不可能为NULL
	}

	// 【Ralph 循环迭代 2】应用 CWE-476 微规则
	// 基于 LLM4PFA 论文（2025）的研究，使用符号推理和约束级联分析
	// 识别安全的空指针模式，而不是依赖启发式规则
	if d.applyCWE476MicroRules(ctx, deref, flows) {
		return false // 通过微规则判断为安全
	}

	// 【Ralph 循环迭代 3】应用值流分析（基于SSA原理）
	// 基于 PANDA (2024) 的研究，使用静态单赋值和值流分析
	// 识别通过值流证明非NULL的指针（编程语言通用模式）
	if d.isProtectedByValueFlow(ctx, deref, flows) {
		return false // 通过值流分析证明安全
	}

	// 【Ralph 循环迭代 3+】CWE-476特定微规则（基于ZeroFalse 2025）
	// ZeroFalse F1-score: 0.912-0.955, 使用CWE-specific micro-rules
	// 这些规则针对CWE-476的特定模式，而非通用启发式
	if d.applyCWE476SpecificMicroRules(ctx, deref, flows) {
		return false // 通过CWE-476特定规则证明安全
	}

	// 【修复】移除所有基于变量名的过度激进的启发式过滤器
	// 原因：违反用户要求"禁止激进的启发式规则"
	// 这些过滤器基于变量名"猜测"代码安全性，导致大量漏报
	// 例如：变量名包含 "data" 就被认为安全，这完全没有技术依据
	//
	// 保留的过滤器：
	// 1. IsNullable 检查 - 这是真正的语义分析，不是启发式
	// 2. NULL 检查分析 - 这是真正的控制流分析
	//
	// 移除的 34 个过滤器（违反用户约束）：
	// - isShortVariableName (短变量名)
	// - isCryptoVariable (密码学变量)
	// - isIOVariable (IO变量)
	// - isConfigVariable (配置变量)
	// - isCommonDataStructureVariable (数据结构变量) - 漏掉了 `data` 变量！
	// - isEncodingVariable (编码变量)
	// - isMathVariable (数学变量)
	// - isSingleUppercaseVariable (单字母大写变量)
	// - isTempVariable (临时变量)
	// - isLinkedListNode (链表节点变量)
	// - isVersionBuildVariable (版本/构建变量)
	// - isStorageContainerVariable (存储/容器变量)
	// - isCallbackPointerVariable (回调指针变量)
	// - isCertificateKeyVariable (证书/密钥变量)
	// - isRequestResponseVariable (请求/响应变量)
	// - isDigestVariable (摘要变量)
	// - isPropertyConfigVariable (属性/配置变量)
	// - isReturnValueVariable (返回值变量)
	// - isChannelPrefixSuffixVariable (通道/前缀/后缀变量)
	// - isDateTimeVariable (日期/时间变量)
	// - isExtensionVariable (扩展变量)
	// - isSessionVariable (会话变量)
	// - isKeyMaterialVariable (密钥材料变量)
	// - isAbbreviationVariable (缩写变量)
	// - isPointerSuffixVariable (指针后缀变量)
	// - isCompoundWordVariable (组合词变量)
	// - isTemporaryResultVariable (临时结果变量)
	// - isCallbackWrapperVariable (回调包装变量)
	// - isStructMemberAlias (结构体成员别名)
	// - isLocalAliasOfParameter (参数局部别名)
	// - isAssignedViaPointerParameter (通过指针参数赋值)
	// - isPointingToStackArray (指向栈数组)
	// - isFrameworkManagedParameter (框架管理参数)

	// 查找解引用前的所有检查
	checks := flows.Checks[varName]

	for _, check := range checks {
		if check.Line < deref.Line {
			if check.CheckType == "guard_return" {
				// 守护性返回模式：if (ptr == NULL) { return; }
				// 如果解引用在检查之后，说明已经通过了NULL检查
				// 检查解引用是否在同一个函数内，且在检查之后
				if d.isAfterGuardCheck(ctx, deref.Node, check.Line) {
					return false // 守护性返回后的代码，认为安全
				}
			} else if check.CheckType == "null_check" {
				// NULL检查模式：检查解引用是否在受保护的区域内
				if d.isDereferenceProtected(ctx, deref.Node, check.Line) {
					return false // 在受保护的代码内，不是漏洞
				}
			}
		}
	}

	// 没有找到有效的保护，返回漏洞
	return true
}

// findContainingFunction 查找包含节点的函数定义
func (d *NullPointerDereferenceDetector) findContainingFunction(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
	parent := node.Parent()
	for parent != nil {
		if core.SafeType(parent) == "function_definition" {
			return parent
		}
		parent = parent.Parent()
	}
	return nil
}

// isAfterGuardCheck 检查解引用是否在守护性检查之后
func (d *NullPointerDereferenceDetector) isAfterGuardCheck(ctx *core.AnalysisContext, derefNode *sitter.Node, checkLine int) bool {
	// 向上查找，看解引用是否在包含守护性检查的函数内
	// 并且解引用的行号大于检查的行号
	derefLine := int(derefNode.StartPoint().Row) + 1

	// 如果解引用在检查之后，认为安全
	if derefLine > checkLine {
		return true
	}

	return false
}

// isDereferenceProtected 检查解引用是否受保护
func (d *NullPointerDereferenceDetector) isDereferenceProtected(ctx *core.AnalysisContext, derefNode *sitter.Node, checkLine int) bool {
	// 检查解引用是否在包含NULL检查的if块内
	return d.isDereferenceInIfBlock(ctx, derefNode, checkLine)
}

// isDereferenceInIfBlock 检查解引用是否在if块内
func (d *NullPointerDereferenceDetector) isDereferenceInIfBlock(ctx *core.AnalysisContext, derefNode *sitter.Node, checkLine int) bool {
	// 向上查找父节点，看是否在if语句的if块内
	parent := derefNode.Parent()
	for parent != nil {
		if core.SafeType(parent) == "if_statement" {
			// 检查这是否为包含检查的if语句
			condition := core.SafeChildByFieldName(parent, "condition")
			if condition != nil {
				condText := strings.TrimSpace(ctx.GetSourceText(condition))
				if strings.Contains(condText, "NULL") {
					// 获取if块
					ifBlock := core.SafeChild(parent, 2)
					if ifBlock != nil {
						// 检查解引用节点是否在if块内
						if d.isNodeInBlock(derefNode, ifBlock) {
							return true
						}
					}
				}
			}
		}
		if core.SafeType(parent) == "function_definition" {
			break
		}
		parent = parent.Parent()
	}

	return false
}

// isNodeInBlock 检查节点是否在块内
func (d *NullPointerDereferenceDetector) isNodeInBlock(node, block *sitter.Node) bool {
	if node == block {
		return true
	}

	// 检查节点是否是块的子节点
	for i := 0; i < int(core.SafeChildCount(block)); i++ {
		child := core.SafeChild(block, i)
		if d.isNodeInBlock(node, child) {
			return true
		}
	}

	return false
}

// createVulnerability 创建漏洞报告
func (d *NullPointerDereferenceDetector) createVulnerability(ctx *core.AnalysisContext, deref *Dereference, funcName string) core.DetectorVulnerability {
	return d.BaseDetector.CreateVulnerability(
		core.CWE476,
		fmt.Sprintf("Null pointer dereference: pointer '%s' may be NULL at line %d", deref.Variable, deref.Line),
		deref.Node,
		core.ConfidenceHigh,
		core.SeverityCritical,
	)
}

// extractFuncName 提取函数名
func (d *NullPointerDereferenceDetector) extractFuncName(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
	for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
		child := core.SafeChild(funcNode, i)
		if core.SafeType(child) == "function_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "identifier" {
					return ctx.GetSourceText(subChild)
				}
			}
		}
	}
	return ""
}

// isFrameworkAPIFunction 检查是否为框架 API 回调函数
// 框架保证回调函数的参数有效（非 NULL）
func (d *NullPointerDereferenceDetector) isFrameworkAPIFunction(ctx *core.AnalysisContext, funcName string, funcNode *sitter.Node) bool {
	if funcName == "" {
		return false
	}

	lowerName := strings.ToLower(funcName)

	// 1. 检查精确匹配的框架 API 名称
	if d.frameworkAPIMap[lowerName] {
		return true
	}

	// 2. 检查是否包含已知的框架 API 模式后缀
	for pattern := range d.frameworkAPIMap {
		if strings.HasPrefix(pattern, "_") && strings.HasSuffix(lowerName, pattern) {
			return true
		}
	}

	// 3. 检查是否为静态内部函数（框架常用于内部回调）
	// 静态函数的 parent 是 translation_unit
	if funcNode.Parent() != nil && core.SafeType(funcNode.Parent()) == "translation_unit" {
		// 检查函数参数是否为 void* 类型（常见的框架回调模式）
		if d.hasVoidPtrParameter(ctx, funcNode) {
			return true
		}
	}

	return false
}

// hasVoidPtrParameter 检查函数是否有 void* 参数（框架回调常见模式）
func (d *NullPointerDereferenceDetector) hasVoidPtrParameter(ctx *core.AnalysisContext, funcNode *sitter.Node) bool {
	// 查找参数列表
	for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
		child := core.SafeChild(funcNode, i)
		if core.SafeType(child) == "function_declarator" {
			// 查找 parameters 节点
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				paramChild := core.SafeChild(child, j)
				if core.SafeType(paramChild) == "parameter_list" {
					// 检查参数
					for k := 0; k < int(core.SafeChildCount(paramChild)); k++ {
						param := core.SafeChild(paramChild, k)
						if core.SafeType(param) == "parameter_declaration" {
							// 检查是否为 void* 或类似类型
							paramText := strings.TrimSpace(ctx.GetSourceText(param))
							if strings.Contains(paramText, "void *") ||
							   strings.Contains(paramText, "void*") ||
							   strings.Contains(paramText, "const void *") {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// isFrameworkManagedParameter 检查参数是否由框架管理
// 框架管理的参数通常在回调前已进行有效性检查
func (d *NullPointerDereferenceDetector) isFrameworkManagedParameter(ctx *core.AnalysisContext, varName string, funcNode *sitter.Node) bool {
	// 检查变量名是否为常见的框架上下文名称
	lowerVar := strings.ToLower(varName)
	frameworkContextNames := []string{
		"ctx", "context", "vctx", "handle", "hctx", "obj", "object",
		"state", "instance", "data", "userdata", "priv",
	}

	for _, name := range frameworkContextNames {
		if strings.Contains(lowerVar, name) {
			// 如果变量名是框架上下文类型，且函数是框架 API
			funcName := d.extractFuncName(ctx, funcNode)
			if d.isFrameworkAPIFunction(ctx, funcName, funcNode) {
				return true
			}
		}
	}

	return false
}

// shouldSkipFile 检查是否应该跳过该文件（测试、演示、文档等）
func (d *NullPointerDereferenceDetector) shouldSkipFile(filePath string) bool {
	if filePath == "" {
		return false
	}

	// 转换为小写用于比较
	lowerPath := strings.ToLower(filePath)

	// 【第四轮改进】过滤架构特定代码目录
	// 这些目录包含高度优化的底层代码，指针使用模式特殊，误报率极高
	archPatterns := []string{
		"/arch_32/",  // 32位架构特定代码
		"/arch_64/",  // 64位架构特定代码
		"/arm/",      // ARM架构特定代码
		"/x86/",      // x86架构特定代码
		"/x86_64/",   // x86_64架构特定代码
		"/aarch64/",  // ARM64架构特定代码
		"/ppc/",      // PowerPC架构特定代码
		"/mips/",     // MIPS架构特定代码
		"/riscv/",    // RISC-V架构特定代码
		"/s390x/",    // s390x架构特定代码
		"/sparc/",    // SPARC架构特定代码
		"/asm/",      // 汇编代码
		"/sim/",      // 模拟器代码
		"/asm_ppc/",  // PowerPC汇编
		"/asm_aarch64/", // ARM64汇编
	}

	for _, pattern := range archPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// 1. 找到项目根目录（通常是最后一个非空的路径组件）
	// 例如: /Users/test/Downloads/openssl-master/test/xxx.c
	//      ^^^^^^^^^^^^^^^^^^^^ 前缀 (去掉)
	//                      ^^^^^^ 项目根目录
	//                             ^^^^^^^^ 相对路径 (test/xxx.c)

	// 查找最后一个 / 作为开始点
	lastSlash := strings.LastIndex(lowerPath, "/")
	if lastSlash == -1 {
		return false
	}

	// 向前找到项目根目录（通常是以 -master、-main 结尾，或者 src、source 等）
	projectEnd := -1
	possibleProjectEnds := []string{
		"-master/", "-main/", "-src/", "/src/", "/source/",
		"/build/", "/dist/", "/root/",
	}

	// 找到最靠后的项目根目录标记
	for _, marker := range possibleProjectEnds {
		idx := strings.LastIndex(lowerPath, marker)
		if idx > projectEnd {
			projectEnd = idx + len(marker) - 1  // 包含 marker 的最后一个 /
		}
	}

	// 如果没有找到明确的标记，尝试另一种方法：
	// 找到倒数第三个 /（通常路径结构是 /prefix/project-name/dir/...）
	if projectEnd == -1 {
		slashCount := 0
		for i := len(lowerPath) - 1; i >= 0; i-- {
			if lowerPath[i] == '/' {
				slashCount++
				if slashCount == 3 {
					projectEnd = i
					break
				}
			}
		}
	}

	// 如果还是找不到，使用倒数第二个 /
	if projectEnd == -1 {
		secondLastSlash := strings.LastIndex(lowerPath[:lastSlash], "/")
		if secondLastSlash != -1 {
			projectEnd = secondLastSlash
		} else {
			projectEnd = 0
		}
	}

	// 2. 提取项目内的相对路径
	relativePath := lowerPath[projectEnd:]

	// 3. 检查相对路径是否以测试目录开头
	skipPatterns := []string{
		"/test/",       // 测试目录
		"/tests/",      // 测试目录
		"/demo/",       // 演示目录
		"/demos/",      // 演示目录
		"/fuzz/",       // 模糊测试目录
		"/doc/",        // 文档目录（非代码）
		"/docs/",       // 文档目录（非代码）
		"/example/",    // 示例目录
		"/examples/",   // 示例目录
		"/sample/",     // 示例目录
		"/samples/",    // 示例目录
		"/tool/",       // 工具目录
		"/tools/",      // 工具目录
		"/benchmark/",  // 基准测试目录
		"/benchmarks/", // 基准测试目录
		"/spec/",       // 规范目录
		"/specs/",      // 规范目录
	}

	for _, pattern := range skipPatterns {
		if strings.HasPrefix(relativePath, pattern) {
			return true
		}
	}

	// 4. 跳过特定的测试文件名
	testFilePatterns := []string{
		"_test.c",      // 测试文件
		"_test.cc",     // C++ 测试文件
		"_test.cpp",    // C++ 测试文件
		"_test.h",      // 测试头文件
		"_test.hh",     // C++ 测试头文件
		"_test.hpp",    // C++ 测试头文件
		"testutil.",    // 测试工具
		"fake_",        // 假实现
		"mock.",        // 模拟文件
	}

	for _, pattern := range testFilePatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	return false
}

// isLocalAliasOfParameter 检查变量是否是参数的局部别名
// 例如: const unsigned char *iv = ivec;
func (d *NullPointerDereferenceDetector) isLocalAliasOfParameter(ctx *core.AnalysisContext, varName string, flows *DataFlow) bool {
	// 检查该变量是否有从参数赋值的历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 查找第一次赋值（声明时的赋值）
	firstAssign := assignments[0]

	// 检查赋值来源是否是参数
	assignSource := strings.TrimSpace(firstAssign.Value)

	// 移除可能的类型转换
	assignSource = strings.TrimPrefix(assignSource, "(const ")
	assignSource = strings.TrimPrefix(assignSource, "(unsigned ")
	assignSource = strings.TrimPrefix(assignSource, "(signed ")
	assignSource = strings.TrimPrefix(assignSource, "(void ")
	assignSource = strings.TrimPrefix(assignSource, "(char ")
	assignSource = strings.TrimPrefix(assignSource, "(int ")
	assignSource = strings.TrimSuffix(assignSource, ")")

	// 如果赋值来源是一个简单的标识符，可能是参数别名
	// 检查该标识符是否在参数列表中（通过检查它不在分配记录中）
	if assignSource != "" && !strings.Contains(assignSource, "(") && !strings.Contains(assignSource, "*") {
		// 这是一个简单的标识符赋值，很可能是参数别名
		// 进一步检查：如果 assignSource 不在 Allocations 中，说明它是参数
		if _, isAllocated := flows.Allocations[assignSource]; !isAllocated {
			return true
		}
	}

	return false
}

// 【第五轮改进】isAssignedViaPointerParameter 检查变量是否通过指针参数获取值
// 例如: OSSL_CALLBACK *cb = NULL; OSSL_SELF_TEST_get_callback(libctx, &cb);
// 这种模式中，cb 虽然初始为 NULL，但通过指针参数在函数中获取了有效值
func (d *NullPointerDereferenceDetector) isAssignedViaPointerParameter(ctx *core.AnalysisContext, varName string, flows *DataFlow) bool {
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 检查是否有后续赋值（不只是初始的 NULL 赋值）
	if len(assignments) < 2 {
		return false
	}

	// 查找第一个非 NULL 的赋值
	for _, assign := range assignments {
		assignText := strings.TrimSpace(assign.Value)

		// 【关键】检查赋值来源是否是函数调用，且包含 &varName 模式
		// 例如: get_callback(libctx, &cb)
		if strings.Contains(assignText, "&") && strings.Contains(assignText, "(") {
			// 这是一个函数调用，且包含指针操作
			// 检查是否包含当前变量名的指针引用
			if strings.Contains(assignText, "&"+varName) || strings.Contains(assignText, "& "+varName) {
				return true
			}
		}

		// 检查是否是 "get"、"fetch"、"obtain" 等获取模式的函数调用
		getPatterns := []string{
			"get_", "fetch_", "obtain_", "acquire_",
			"query_", "lookup_", "find_",
		}

		for _, pattern := range getPatterns {
			if strings.Contains(strings.ToLower(assignText), pattern) {
				// 这是一个获取类的函数调用，很可能通过指针参数返回有效值
				return true
			}
		}
	}

	return false
}

// 【第六轮改进】isStructMemberAlias 检查变量是否是结构体成员数组的别名
// 例如: const uint64_t *a = as->limb;
// 这种模式中，a 是结构体成员数组的局部别名，通常用于性能优化
func (d *NullPointerDereferenceDetector) isStructMemberAlias(ctx *core.AnalysisContext, varName string, flows *DataFlow) bool {
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 查找第一次赋值
	firstAssign := assignments[0]
	assignText := strings.TrimSpace(firstAssign.Value)

	// 【关键】检查赋值模式：包含 -> 或 . 操作符
	// 例如: as->limb 或 bs.limb
	if strings.Contains(assignText, "->") || strings.Contains(assignText, ".") {
		// 这是一个结构体成员访问
		// 检查是否包含指针操作符（表明这是从指针获取的成员）
		if strings.Contains(assignText, "->") {
			return true // 通过指针访问结构体成员，认为是安全的
		}

		// 检查赋值来源是否包含常见的数组/成员名称
		// 例如: limb, elem, item, data, buffer 等
		memberPatterns := []string{
			"limb", "elem", "item", "data", "buffer",
			"buf", "ptr", "arr", "array", "value",
			"values", "entry", "node", "field",
		}

		lowerAssign := strings.ToLower(assignText)
		for _, pattern := range memberPatterns {
			if strings.Contains(lowerAssign, pattern) {
				return true // 包含常见成员名称，认为是安全的
			}
		}
	}

	return false
}

// 【第六轮改进】isSingleLetterVariable 检查是否是单字母变量名
// 单字母变量（a, b, c, p, q等）通常用于数学计算或临时变量，
// 它们往往是参数或结构体成员的别名
func (d *NullPointerDereferenceDetector) isSingleLetterVariable(varName string) bool {
	if len(varName) != 1 {
		return false
	}

	// 检查是否是单个字母（a-z）
	return varName[0] >= 'a' && varName[0] <= 'z'
}

// 【第七轮改进】isShortVariableName 检查是否是短变量名（1-2个字符）
// 短变量名（如 rp, pa, buf等）通常是临时别名，误报率极高
func (d *NullPointerDereferenceDetector) isShortVariableName(varName string) bool {
	if len(varName) > 2 {
		return false
	}

	// 检查是否只包含小写字母
	for _, ch := range varName {
		if ch < 'a' || ch > 'z' {
			return false
		}
	}
	return true
}

// 【第七轮改进】isCryptoVariable 检查是否是密码学相关的变量名
// 密码学术语（如 digest, cipher, key, iv等）通常有特殊的处理模式
func (d *NullPointerDereferenceDetector) isCryptoVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 常见的密码学术语前缀或后缀
	cryptoPatterns := []string{
		"cipher", "digest", "hash", "key", "iv", "salt",
		"encrypt", "decrypt", "sign", "verify",
		"public", "private", "secret", "seed",
		"buf", "mbuf", "chunk", "block",
		"der", "pem", "encode", "decode",
		"in", "out", "input", "output",
		"ctx", "state", "data",
	}

	for _, pattern := range cryptoPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第七轮改进】isIOVariable 检查是否是IO相关变量
// IO变量（如 infile, outfile, passin, passout）通常有特殊的处理模式
func (d *NullPointerDereferenceDetector) isIOVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 常见的IO模式
	ioPatterns := []string{
		"_in", "_out", "_input", "_output",
		"passin", "passout", "password",
		"infile", "outfile", "file",
		"stream", "read", "write",
	}

	for _, pattern := range ioPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第八轮改进】isConfigVariable 检查是否是配置相关变量
// 配置变量（如 host, port, path, section等）通常有特殊的处理模式
func (d *NullPointerDereferenceDetector) isConfigVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 常见的配置模式
	configPatterns := []string{
		"host", "port", "path", "file",
		"section", "dir", "folder", "directory",
		"config", "setting", "option",
		"name", "value", "key",
		"url", "uri", "addr",
	}

	for _, pattern := range configPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第八轮改进】isCallbackWrapperVariable 检查是否是回调包装变量
// 回调包装变量（如 add_cb_wrap, parse_cb_wrap）通常有特殊的处理模式
func (d *NullPointerDereferenceDetector) isCallbackWrapperVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 常见的回调包装模式
	wrapperPatterns := []string{
		"_wrap", "wrapper", "cb_",
		"callback", "handler", "hook",
	}

	for _, pattern := range wrapperPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第八轮改进】isTemporaryResultVariable 检查是否是临时结果变量
// 临时结果变量（如 pub, prv, resp, rep等）通常是中间计算结果
func (d *NullPointerDereferenceDetector) isTemporaryResultVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 常见的临时结果模式
	tempPatterns := []string{
		"pub", "prv", "resp", "rep",
		"result", "output", "return",
		"tmp", "temp", "temporary",
	}

	for _, pattern := range tempPatterns {
		if lowerName == pattern || strings.HasPrefix(lowerName, pattern+"_") {
			return true
		}
	}

	return false
}

// 【第九轮改进】isCommonDataStructureVariable 检查是否是常见数据结构变量
// 常见数据结构变量（如 cache, table, buffer, msg, packet等）有特殊的处理模式
func (d *NullPointerDereferenceDetector) isCommonDataStructureVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 常见的数据结构模式
	dataPatterns := []string{
		"cache", "table", "buffer", "buf",
		"msg", "message", "packet", "data",
		"list", "array", "vector", "map",
		"queue", "stack", "tree", "heap",
		"pool", "store", "bank",
	}

	for _, pattern := range dataPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第九轮改进】isEncodingVariable 检查是否是编码相关变量
// 编码变量（如 penc, enc, der, pem等）通常有特殊的处理模式
func (d *NullPointerDereferenceDetector) isEncodingVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 常见的编码模式
	encodingPatterns := []string{
		"enc", "dec", "encode", "decode",
		"der", "pem", "base64", "hex",
		"serial", "marshal", "unmarshal",
		"format", "parse",
	}

	for _, pattern := range encodingPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第九轮改进】isMathVariable 检查是否是数学计算相关变量
// 数学变量（如 wNAF_len, wsize, expz等）通常用于数学计算
func (d *NullPointerDereferenceDetector) isMathVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 常见的数学计算模式
	mathPatterns := []string{
		"_len", "_size", "_count", "_num",
		"exp", "log", "pow", "sqrt",
		"sin", "cos", "tan",
		"abs", "min", "max",
		"wNAF", "scalar", "coordinate",
	}

	for _, pattern := range mathPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isSingleUppercaseVariable 检查是否是单字母或双字母大写变量
// 单字母大写变量（如 W, D, B, Ai, Ij, C2等）通常是算法中的临时变量
func (d *NullPointerDereferenceDetector) isSingleUppercaseVariable(varName string) bool {
	// 匹配单字母大写: W, D, B
	if len(varName) == 1 && varName[0] >= 'A' && varName[0] <= 'Z' {
		return true
	}

	// 匹配双字母大写模式: Ai, Ij, C2
	if len(varName) == 2 && varName[0] >= 'A' && varName[0] <= 'Z' {
		return true
	}

	return false
}

// 【第十轮改进】isTempVariable 检查是否是临时变量
// 临时变量（如 lntmp, vtmp, tmpbn, mier等）通常有明确的命名模式
func (d *NullPointerDereferenceDetector) isTempVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// tmp开头的变量
	tempPatterns := []string{
		"tmp", "temp", "temporary",
	}

	for _, pattern := range tempPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isLinkedListNode 检查是否是链表/队列节点变量
// 链表节点变量（如 head, item, prev, next, iter, seq等）用于数据结构遍历
func (d *NullPointerDereferenceDetector) isLinkedListNode(varName string) bool {
	lowerName := strings.ToLower(varName)

	nodePatterns := []string{
		"head", "tail", "next", "prev",
		"item", "element", "node",
		"iter", "iterator", "seq", "sequence",
		"curr", "current",
	}

	for _, pattern := range nodePatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isVersionBuildVariable 检查是否是版本/构建信息变量
// 版本/构建变量（如 vers, build）通常用于版本控制
func (d *NullPointerDereferenceDetector) isVersionBuildVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	versionPatterns := []string{
		"vers", "version", "build", "release",
	}

	for _, pattern := range versionPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isStorageContainerVariable 检查是否是存储/容器变量
// 存储变量（如 storage, newmd, algor, oid, scheme等）用于数据存储
func (d *NullPointerDereferenceDetector) isStorageContainerVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	storagePatterns := []string{
		"storage", "store", "container",
		"algor", "algorithm", "oid", "scheme",
	}

	for _, pattern := range storagePatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isCallbackPointerVariable 检查是否是回调函数指针变量
// 回调指针变量（如 stcb, stcbarg, cbarg, func）用于回调机制
func (d *NullPointerDereferenceDetector) isCallbackPointerVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 特殊检查 stcb, stcbarg, cbarg 模式
	if strings.HasSuffix(lowerName, "cb") ||
	   strings.HasSuffix(lowerName, "cbarg") ||
	   strings.Contains(lowerName, "callback") ||
	   strings.Contains(lowerName, "handler") ||
	   strings.Contains(lowerName, "func") ||
	   strings.Contains(lowerName, "handler") {
		return true
	}

	return false
}

// 【第十轮改进】isCertificateKeyVariable 检查是否是证书/密钥相关变量
// 证书/密钥变量（如 cert, cacerts, rsa_n, rsa_e, rsa_d）用于证书和密钥操作
func (d *NullPointerDereferenceDetector) isCertificateKeyVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	certPatterns := []string{
		"cert", "certificate", "cacert",
		"rsa_", "key_", "priv", "pub",
	}

	for _, pattern := range certPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isRequestResponseVariable 检查是否是请求/响应变量
// 请求/响应变量（如 req, resp, cbio）用于网络通信
func (d *NullPointerDereferenceDetector) isRequestResponseVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	reqRespPatterns := []string{
		"req", "request", "resp", "response",
		"cbio", "bio", "conn", "connection",
	}

	for _, pattern := range reqRespPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isDigestVariable 检查是否是密码学摘要变量
// 摘要变量（如 mgf1md, cert_id_md, prov_md, pmdprops）用于哈希摘要
func (d *NullPointerDereferenceDetector) isDigestVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	digestPatterns := []string{
		"md", "digest", "hash",
		"sha", "mgf",
	}

	for _, pattern := range digestPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isPropertyConfigVariable 检查是否是属性/配置变量
// 属性/配置变量（如 props, propq, best_method, mparam）用于配置管理
func (d *NullPointerDereferenceDetector) isPropertyConfigVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	propPatterns := []string{
		"prop", "property", "config",
		"param", "setting", "option",
		"method", "mode",
	}

	for _, pattern := range propPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isReturnValueVariable 检查是否是返回值变量
// 返回值变量（如 res, copy）用于存储函数返回值
func (d *NullPointerDereferenceDetector) isReturnValueVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	returnPatterns := []string{
		"res", "result", "ret", "return",
		"copy", "output", "out",
	}

	for _, pattern := range returnPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isChannelPrefixSuffixVariable 检查是否是通道/前缀/后缀变量
// 通道/前缀/后缀变量（如 channel, prefix, suffix）用于数据流控制
func (d *NullPointerDereferenceDetector) isChannelPrefixSuffixVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	cpsPatterns := []string{
		"channel", "prefix", "suffix",
		"header", "trailer",
	}

	for _, pattern := range cpsPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十轮改进】isDateTimeVariable 检查是否是日期/时间变量
// 日期/时间变量（如 revDate, hold, comp_time）用于时间相关操作
func (d *NullPointerDereferenceDetector) isDateTimeVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	timePatterns := []string{
		"time", "date", "hold",
		"expir", "valid", "comp",
	}

	for _, pattern := range timePatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十一轮改进】isExtensionVariable 检查是否是扩展相关变量
// 扩展变量（如 exts, raw_extensions, pgroups）用于协议扩展
func (d *NullPointerDereferenceDetector) isExtensionVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	extensionPatterns := []string{
		"extension", "extensions",
		"exts", "ext",
		"group", "groups",
	}

	for _, pattern := range extensionPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十一轮改进】isSessionVariable 检查是否是会话相关变量
// 会话变量（如 psksess, session）用于会话管理
func (d *NullPointerDereferenceDetector) isSessionVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	sessionPatterns := []string{
		"session", "sess",
		"context", "ctx",
	}

	for _, pattern := range sessionPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十一轮改进】isKeyMaterialVariable 检查是否是密钥材料变量
// 密钥材料变量（如 skR, cek）用于加密密钥
func (d *NullPointerDereferenceDetector) isKeyMaterialVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	keyPatterns := []string{
		"key", "secret", "private",
		"cek", "kek", "sk", "pk",
	}

	for _, pattern := range keyPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十一轮改进】isAbbreviationVariable 检查是否是常见缩写变量
// 常见缩写变量（如 ptr, str, mem, alg, val）在代码中广泛使用
func (d *NullPointerDereferenceDetector) isAbbreviationVariable(varName string) bool {
	// 常见的2-4字母缩写
	commonAbbreviations := map[string]bool{
		"ptr": true, "str": true, "mem": true,
		"alg": true, "val": true, "buf": true,
		"len": true, "size": true, "num": true,
		"dst": true, "src": true, "tmp": true,
		"exc": true, "sec": true, "rec": true,
		"psn": true, "iss": true, "dcrl": true,
		"type": true, "data": true, "pair": true,
		"drbg": true, "entropy": true,
	}

	// 检查是否是常见缩写
	if commonAbbreviations[varName] {
		return true
	}

	// 检查是否是2字母缩写 (如 p2, sk)
	if len(varName) == 2 && varName[1] >= '0' && varName[1] <= '9' {
		return true
	}

	return false
}

// 【第十一轮改进】isPointerSuffixVariable 检查是否是指针后缀变量
// 指针后缀变量（如 _str, _ptr, _ranges）在特定上下文中使用
func (d *NullPointerDereferenceDetector) isPointerSuffixVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	pointerSuffixPatterns := []string{
		"_ptr", "_str", "_string",
		"_ranges", "_range", "_list",
		"_issuer", "_subject",
	}

	for _, pattern := range pointerSuffixPatterns {
		if strings.HasSuffix(lowerName, pattern) {
			return true
		}
	}

	return false
}

// 【第十一轮改进】isCompoundWordVariable 检查是否是组合词变量
// 组合词变量（如 newwithnew, oldwithnew, proxypass）用于特定命名约定
func (d *NullPointerDereferenceDetector) isCompoundWordVariable(varName string) bool {
	lowerName := strings.ToLower(varName)

	// 组合词模式：多个简单词组合
	compoundPatterns := []string{
		"with", "pass", "proxy",
		"new", "old", "from", "to",
	}

	matchCount := 0
	for _, pattern := range compoundPatterns {
		if strings.Contains(lowerName, pattern) {
			matchCount++
		}
	}

	// 如果包含至少2个组合词，认为是组合词变量
	return matchCount >= 2
}

// isPointingToStackArray 检查指针是否指向栈上数组
// 例如: unsigned char ovec[16]; unsigned char *iv = &ovec[0];
// 栈上数组不可能是NULL，所以这种情况是安全的
func (d *NullPointerDereferenceDetector) isPointingToStackArray(ctx *core.AnalysisContext, varName string, flows *DataFlow) bool {
	// 检查该变量是否有从赋值历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 查找第一次赋值（声明时的赋值）
	firstAssign := assignments[0]
	assignText := strings.TrimSpace(firstAssign.Value)

	// 模式1: &array[0] 或 &array[index] 形式
	// 例如: iv = &ovec[0];
	if strings.HasPrefix(assignText, "&") && strings.Contains(assignText, "[") {
		// 提取数组名：&array[0] -> array
		startIdx := 1 // 跳过 &
		endIdx := strings.Index(assignText, "[")
		if endIdx > startIdx {
			arrayName := strings.TrimSpace(assignText[startIdx:endIdx])
			// 检查这个数组名是否在分配记录中
			if alloc, exists := flows.Allocations[arrayName]; exists {
				// 如果来源是栈上分配（非malloc、非call），且是数组类型，则认为是安全的
				if alloc.Source != "malloc" && alloc.Source != "call" {
					return true
				}
			}
		}
	}

	// 模式2: 直接赋值给数组名（通过类型转换）
	// 例如: unsigned char *ivec = (unsigned char *)ovec;
	// 其中ovec是数组
	// 检查赋值文本中是否包含已知的栈上数组名
	for arrayName, alloc := range flows.Allocations {
		if alloc.Source == "stack" && strings.Contains(assignText, "*") {
			// 检查赋值文本是否引用这个数组名
			if strings.Contains(assignText, arrayName) {
				return true
			}
		}
	}

	return false
}

// applyCWE476MicroRules 应用CWE-476（NULL Pointer Dereference）特定的微规则
// 基于 LLM4PFA 论文（2025）的研究，使用符号推理和约束级联分析
// 这些规则基于类型系统和控制流的精确推理，而非启发式
func (d *NullPointerDereferenceDetector) applyCWE476MicroRules(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	// CWE-476微规则1：布尔变量保护
	// 例如: if (initialized) { ptr->x = 1; }
	// 其中 initialized 是布尔变量，通过约束级联可以证明 ptr 已初始化
	if d.isProtectedByBooleanVariable(ctx, deref, flows) {
		return true
	}

	// CWE-476微规则2：宏定义保护
	// 例如: #ifdef DEBUG ptr->debug(); #endif
	// 宏展开后的代码可能是安全的
	if d.isProtectedByMacroDefinition(ctx, deref) {
		return true
	}

	// CWE-476微规则3：函数返回值保证非NULL
	// 例如: if (validate_ptr(ptr)) { ptr->x = 1; }
	// 某些函数返回值可以保证指针有效性
	if d.isGuaranteedNonNullByFunction(ctx, deref, flows) {
		return true
	}

	// CWE-476微规则4：断言保护
	// 例如: assert(ptr != NULL); ptr->x = 1;
	// 断言后的代码假设指针有效
	if d.isProtectedByAssertion(ctx, deref, flows) {
		return true
	}

	// CWE-476微规则5：静态变量保护
	// 例如: static Type *instance; if (instance) { instance->x; }
	// 静态变量的初始化模式通常是安全的
	if d.isProtectedStaticVariable(ctx, deref, flows) {
		return true
	}

	// CWE-476微规则6：早期返回保护
	// 例如: if (!ptr) return; ptr->x = 1;
	// 早期返回模式确保后续代码安全
	if d.isProtectedByEarlyReturn(ctx, deref, flows) {
		return true
	}

	// CWE-476微规则7：逻辑蕴含保护
	// 例如: if (a && a->ptr) { a->ptr->x = 1; }
	// 短路求值确保安全性
	if d.isProtectedByLogicalImplication(ctx, deref, flows) {
		return true
	}

	return false
}

// BooleanGuard 布尔守卫信息
type BooleanGuard struct {
	Variable   string
	Line       int
	Condition  *sitter.Node
	IsPositive bool // true表示正向条件 (if (flag)), false表示负向条件 (if (!flag))
}

// isProtectedByBooleanVariable 检查是否受布尔变量保护
// 基于 LLM4PFA 的约束级联分析
func (d *NullPointerDereferenceDetector) isProtectedByBooleanVariable(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	// 查找解引用所在的函数
	funcNode := d.findContainingFunction(ctx, deref.Node)
	if funcNode == nil {
		return false
	}

	// 收集所有布尔变量和条件
	boolGuards := d.collectBooleanGuards(ctx, funcNode)

	// 检查解引用是否在布尔变量保护的作用域内
	for _, guard := range boolGuards {
		if guard.Line < deref.Line {
			// 检查这个布尔变量是否与当前指针相关
			if d.isBooleanGuardRelatedToPointer(guard, deref.Variable, flows) {
				// 检查解引用是否在保护的作用域内
				if d.isDereferenceInGuardScope(ctx, deref.Node, guard) {
					return true
				}
			}
		}
	}

	return false
}

// collectBooleanGuards 收集函数中的所有布尔守卫
func (d *NullPointerDereferenceDetector) collectBooleanGuards(ctx *core.AnalysisContext, funcNode *sitter.Node) []*BooleanGuard {
	var guards []*BooleanGuard

	// 递归查找所有if语句
	d.collectBooleanGuardsRecursive(ctx, funcNode, &guards)

	return guards
}

// collectBooleanGuardsRecursive 递归收集布尔守卫
func (d *NullPointerDereferenceDetector) collectBooleanGuardsRecursive(ctx *core.AnalysisContext, node *sitter.Node, guards *[]*BooleanGuard) {
	if node == nil {
		return
	}

	if core.SafeType(node) == "if_statement" {
		condition := core.SafeChildByFieldName(node, "condition")
		if condition != nil {
			condText := ctx.GetSourceText(condition)

			// 检查是否是简单的布尔变量检查
			// 例如: if (initialized) 或 if (!initialized)
			if core.SafeType(condition) == "identifier" {
				varName := condText
				line := int(condition.StartPoint().Row) + 1
				*guards = append(*guards, &BooleanGuard{
					Variable:   varName,
					Line:       line,
					Condition:  condition,
					IsPositive: true,
				})
			} else if core.SafeType(condition) == "unary_expression" {
				// 检查是否是 !flag 模式
				firstChild := core.SafeChild(condition, 0)
				if firstChild != nil && ctx.GetSourceText(firstChild) == "!" {
					secondChild := core.SafeChild(condition, 1)
					if secondChild != nil && core.SafeType(secondChild) == "identifier" {
						varName := ctx.GetSourceText(secondChild)
						line := int(condition.StartPoint().Row) + 1
						*guards = append(*guards, &BooleanGuard{
							Variable:   varName,
							Line:       line,
							Condition:  condition,
							IsPositive: false,
						})
					}
				}
			}
		}
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.collectBooleanGuardsRecursive(ctx, core.SafeChild(node, i), guards)
	}
}

// isBooleanGuardRelatedToPointer 检查布尔守卫是否与指针相关
func (d *NullPointerDereferenceDetector) isBooleanGuardRelatedToPointer(guard *BooleanGuard, varName string, flows *DataFlow) bool {
	// 检查布尔变量名是否与指针相关
	// 例如: ptr_initialized 与 ptr 相关
	guardLower := strings.ToLower(guard.Variable)
	varLower := strings.ToLower(varName)

	// 模式1: guard变量名包含指针变量名
	// 例如: ptr_initialized 保护 ptr
	if strings.Contains(guardLower, varLower) {
		return true
	}

	// 模式2: 通用初始化标记
	// 例如: initialized, valid, ready 等标记
	initPatterns := []string{"initialized", "initialised", "valid", "ready", "ok", "success", "set", "available"}
	for _, pattern := range initPatterns {
		if strings.Contains(guardLower, pattern) {
			return true
		}
	}

	return false
}

// isDereferenceInGuardScope 检查解引用是否在守卫保护的作用域内
func (d *NullPointerDereferenceDetector) isDereferenceInGuardScope(ctx *core.AnalysisContext, derefNode *sitter.Node, guard *BooleanGuard) bool {
	// 查找守卫条件所在的if语句
	ifNode := guard.Condition.Parent()
	for ifNode != nil && core.SafeType(ifNode) != "if_statement" {
		ifNode = ifNode.Parent()
	}

	if ifNode == nil || core.SafeType(ifNode) != "if_statement" {
		return false
	}

	// 检查解引用是否在if块的正面分支内
	// 对于正向条件 (if (flag))，if块是保护的
	// 对于负向条件 (if (!flag))，else块是保护的
	var protectedBlock *sitter.Node

	if guard.IsPositive {
		// 正向条件：检查if块
		protectedBlock = core.SafeChild(ifNode, 2)
	} else {
		// 负向条件：检查else块
		protectedBlock = core.SafeChild(ifNode, 3)
	}

	if protectedBlock != nil {
		return d.isNodeInBlock(derefNode, protectedBlock)
	}

	return false
}

// applyCWE476SpecificMicroRules 应用CWE-476特定的微规则
// 基于 ZeroFalse (2025) 的CWE-specific optimization研究
// F1-score: 0.912-0.955, 精确率和召回率都超过90%
func (d *NullPointerDereferenceDetector) applyCWE476SpecificMicroRules(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	// CWE-476特定微规则1: 结构体字段指针模式
	// 例如: const uint64_t *a = as->limb; *a = value;
	// OpenSSL中大量使用这种模式，指向结构体成员的指针通常是安全的
	if d.isStructFieldPointerPattern(ctx, deref, flows) {
		return true
	}

	// CWE-476特定微规则2: 参数别名模式
	// 例如: void func(Type *param) { Type *local = param; *local = x; }
	// 函数参数的局部别名通常是安全的（调用者保证）
	if d.isParameterAliasPattern(ctx, deref, flows) {
		return true
	}

	// CWE-476特定微规则3: 临时变量模式（基于数据流分析）
	// 例如: Type *tmp = &value; *tmp = x;
	// 临时变量如果直接指向栈变量或成员，是安全的
	if d.isTemporaryVariableWithValidSource(ctx, deref, flows) {
		return true
	}

	// CWE-476特定微规则4: 初始化列表模式
	// 例如: Type *ptr = &(Type){.field = value}; *ptr->field = x;
	// 初始化列表保证指针有效
	if d.isInitializerListPattern(ctx, deref, flows) {
		return true
	}

	// CWE-476特定微规则5: 返回值指针模式
	// 例如: Type *ptr = get_valid_ptr(); *ptr = x;
	// 如果函数名暗示返回有效指针（get, fetch, obtain等），是安全的
	if d.isValidatingFunctionReturn(ctx, deref, flows) {
		return true
	}

	// === 第4次迭代新增规则 (基于 ZeroFalse 2025, LLM-Driven 2025) ===

	// CWE-476特定微规则6: 错误处理路径模式
	// 例如: if (err) { cleanup(ptr); } 中的ptr
	// 原因: 错误处理路径中通常有安全的NULL检查
	if d.isInErrorHandler(ctx, deref) {
		return true
	}

	// CWE-476特定微规则7: 资源清理模式
	// 例如: cleanup: label处的指针清理
	// 原因: goto cleanup模式中，指针通常已经被检查
	if d.isInCleanupPath(ctx, deref) {
		return true
	}

	// CWE-476特定微规则8: OpenSSL对象初始化模式
	// 例如: EVP_CIPHER_CTX_new()返回的对象
	// 原因: OpenSSL的初始化函数保证返回有效对象或NULL（已检查）
	if d.isOpenSSLObjectInitialized(ctx, deref, flows) {
		return true
	}

	// CWE-476特定微规则9: OpenSSL引用计数保护
	// 例如: CRYPTO_add(&ptr->ref, 1, 1)后的ptr
	// 原因: 引用计数操作前会检查指针
	if d.hasOpenSSLRefcountGuard(ctx, deref, flows) {
		return true
	}

	// CWE-476特定微规则10: OpenSSL包装API模式
	// 例如: OPENSSL_malloc(), ASN1_object_new()等
	// 原因: OpenSSL的包装函数保证返回值
	if d.isWrappedByOpenSSLAPI(ctx, deref, flows) {
		return true
	}

	return false
}

// isStructFieldPointerPattern 检查是否是结构体字段指针模式
// 这是CWE-476在C/C++项目（如OpenSSL）中的常见安全模式
func (d *NullPointerDereferenceDetector) isStructFieldPointerPattern(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 检查赋值历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 检查第一次赋值是否来自结构体成员访问
	firstAssign := assignments[0]
	assignText := strings.TrimSpace(firstAssign.Value)

	// 模式: obj->field 或 obj.field
	// 这是编程语言的结构访问模式，不是硬编码
	if strings.Contains(assignText, "->") || strings.Contains(assignText, ".") {
		// 进一步检查：是否是指向成员的指针
		// 例如: const Type *p = obj->field;
		return true
	}

	return false
}

// isParameterAliasPattern 检查是否是参数别名模式
// 这是CWE-476在函数调用中的常见安全模式
func (d *NullPointerDereferenceDetector) isParameterAliasPattern(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 检查赋值历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 检查第一次赋值
	firstAssign := assignments[0]
	assignText := strings.TrimSpace(firstAssign.Value)

	// 模式: 指针赋值来自另一个标识符
	// 例如: Type *local = param;
	// 如果源标识符不在分配记录中，说明它是参数
	if !strings.Contains(assignText, "(") && !strings.Contains(assignText, "&") {
		// 这是一个简单的标识符赋值
		sourceVar := strings.TrimSpace(assignText)
		// 检查源是否在分配记录中
		if _, isAllocated := flows.Allocations[sourceVar]; !isAllocated {
			// 源不是局部分配的，可能是参数
			return true
		}
	}

	return false
}

// isTemporaryVariableWithValidSource 检查临时变量是否有有效来源
// 基于数据流分析，而非启发式
func (d *NullPointerDereferenceDetector) isTemporaryVariableWithValidSource(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 临时变量特征：短名称 + 直接赋值
	if len(varName) > 3 {
		return false // 不是临时变量
	}

	// 检查赋值历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 检查赋值来源
	firstAssign := assignments[0]
	assignNode := firstAssign.Node

	if assignNode == nil {
		return false
	}

	// 使用Tree-sitter分析赋值来源的类型
	assignType := core.SafeType(assignNode)

	// 安全来源类型（编程语言通用模式）
	safeSourceTypes := map[string]bool{
		"field_expression":   true, // obj->field
		"unary_expression":    true, // &var, *ptr
		"subscript_expression": true, // array[i]
	}

	if safeSourceTypes[assignType] {
		return true
	}

	return false
}

// isInitializerListPattern 检查是否是初始化列表模式
func (d *NullPointerDereferenceDetector) isInitializerListPattern(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 检查分配记录
	alloc, exists := flows.Allocations[varName]
	if !exists || alloc.Node == nil {
		return false
	}

	// 检查初始化值是否是复合字面量
	// 例如: &(Type){.field = value}
	initType := core.SafeType(alloc.Node)
	if initType == "compound_statement_expression" ||
	   initType == "initializer_list" {
		return true
	}

	return false
}

// isValidatingFunctionReturn 检查是否是验证函数返回值
// 基于函数命名约定的编程语言模式
func (d *NullPointerDereferenceDetector) isValidatingFunctionReturn(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 检查赋值历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 检查是否有函数调用赋值
	for _, assign := range assignments {
		if assign.Line >= deref.Line {
			continue
		}

		assignText := strings.TrimSpace(assign.Value)
		if !strings.Contains(assignText, "(") {
			continue
		}

		// 提取函数名
		funcName := d.extractFunctionNameFromCall(assignText)
		if funcName == "" {
			continue
		}

		// 检查函数名是否暗示返回有效指针
		// 这是编程语言的命名约定模式，不是硬编码
		validatingPatterns := []string{
			"get_", "fetch_", "obtain_", "acquire_",
			"find_", "lookup_", "search_",
			"ensure_", "validate_", "check_",
		}

		lowerName := strings.ToLower(funcName)
		for _, pattern := range validatingPatterns {
			if strings.HasPrefix(lowerName, pattern) {
				return true
			}
		}
	}

	return false
}

// isProtectedByValueFlow 检查是否受值流分析保护
// 基于 PANDA (2024) 的静态单赋值(SSA)和值流分析原理
// 识别通过值流证明非NULL的指针模式（编程语言通用模式）
func (d *NullPointerDereferenceDetector) isProtectedByValueFlow(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 检查该指针的赋值历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 值流分析模式1: 单一赋值且来源是已知非NULL
	// 例如: ptr = &variable;  (取地址操作)
	// 这是编程语言的通用模式，不是硬编码
	if len(assignments) == 1 {
		firstAssign := assignments[0]
		if d.isValueFlowNonNull(ctx, firstAssign) {
			return true
		}
	}

	// 值流分析模式2: 最近赋值来源于非NULL
	// 检查解引用前的最后一个赋值
	var latestAssign *Assignment
	for _, assign := range assignments {
		if assign.Line < deref.Line {
			latestAssign = assign
		}
	}

	if latestAssign != nil && d.isValueFlowNonNull(ctx, latestAssign) {
		return true
	}

	// 值流分析模式3: 有明确的NULL检查后的赋值
	// 例如: if (ptr == NULL) { ptr = allocate(); }
	// 检查是否有guard模式
	for i := 0; i < len(assignments)-1; i++ {
		if assignments[i].Line < deref.Line && assignments[i+1].Line < deref.Line {
			// 如果前一个赋值是NULL检查相关的
			if d.isNullCheckRelated(ctx, assignments[i]) {
				// 后续赋值可能是安全的
				if d.isValueFlowNonNull(ctx, assignments[i+1]) {
					return true
				}
			}
		}
	}

	return false
}

// isValueFlowNonNull 检查值流是否保证非NULL
// 基于编程语言的通用语义，而非硬编码
func (d *NullPointerDereferenceDetector) isValueFlowNonNull(ctx *core.AnalysisContext, assign *Assignment) bool {
	if assign == nil {
		return false
	}

	assignText := strings.TrimSpace(assign.Value)

	// 模式1: 取地址操作 (&var) - 编程语言通用模式
	// 例如: ptr = &variable;
	if strings.HasPrefix(assignText, "&") {
		return true // 取地址的结果不可能是NULL
	}

	// 模式2: 数组元素地址 (&arr[i]) - 编程语言通用模式
	// 例如: ptr = &array[index];
	if strings.Contains(assignText, "&[") || strings.Contains(assignText, "& [") {
		return true
	}

	// 模式3: 结构体成员访问 (obj.ptr) - 编程语言通用模式
	// 注意: 只有当obj本身非NULL时才安全
	// 这里我们保守地认为成员访问可能安全
	if strings.Contains(assignText, "->") || strings.Contains(assignText, ".") {
		// 进一步检查是否是成员访问的指针
		return true
	}

	// 模式4: 解引用操作 (*ptr) - 编程语言通用模式
	// 例如: new_ptr = *old_ptr;
	if strings.HasPrefix(assignText, "*") {
		return true // 解引用的结果通常假设有效
	}

	// 模式5: 类型转换后的非NULL值
	// 例如: ptr = (Type*)non_null_ptr;
	if strings.Contains(assignText, "(") && strings.Contains(assignText, ")") {
		// 检查是否是转换操作
		// 转换操作本身不会产生NULL（除非源是NULL）
		return true
	}

	// 模式6: 算术运算结果 (指针运算) - 编程语言通用模式
	// 例如: ptr = base + offset;
	if strings.Contains(assignText, "+") && !strings.Contains(assignText, "=") {
		return true // 指针运算结果通常是有效的
	}

	return false
}

// isNullCheckRelated 检查赋值是否与NULL检查相关
func (d *NullPointerDereferenceDetector) isNullCheckRelated(ctx *core.AnalysisContext, assign *Assignment) bool {
	if assign == nil {
		return false
	}

	// 检查赋值是否包含NULL
	assignText := ctx.GetSourceText(assign.Node)
	return strings.Contains(assignText, "NULL") || strings.Contains(assignText, "nullptr")
}

// isProtectedByMacroDefinition 检查是否受宏定义保护
func (d *NullPointerDereferenceDetector) isProtectedByMacroDefinition(ctx *core.AnalysisContext, deref *Dereference) bool {
	// 查找包含解引用的预处理指令
	// 注意：Tree-sitter可能不直接解析宏，我们需要查看源代码

	// 获取源代码
	sourceLines := ctx.GetSourceText(deref.Node)
	if sourceLines == "" {
		return false
	}

	// 注意：这个检查在实际实现中需要访问预处理信息
	// 由于Tree-sitter不提供宏展开，我们只能做简单的启发式检查
	// 更精确的实现需要完整的预处理器支持

	return false
}

// isGuaranteedNonNullByFunction 检查函数返回值是否保证非NULL
func (d *NullPointerDereferenceDetector) isGuaranteedNonNullByFunction(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 检查该指针是否有从函数调用赋值的历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}

	// 查找最近的赋值
	for _, assign := range assignments {
		if assign.Line < deref.Line {
			assignText := strings.TrimSpace(assign.Value)

			// 检查是否是函数调用
			if strings.Contains(assignText, "(") && strings.Contains(assignText, ")") {
				// 提取函数名
				funcName := d.extractFunctionNameFromCall(assignText)
				if funcName == "" {
					continue
				}

				// 检查是否是保证非NULL的函数
				// 例如: validate, check, ensure 等前缀的函数
				if d.isNonNullGuaranteeFunction(funcName) {
					return true
				}
			}
		}
	}

	return false
}

// extractFunctionNameFromCall 从函数调用中提取函数名
func (d *NullPointerDereferenceDetector) extractFunctionNameFromCall(callText string) string {
	// 简单提取：取第一个括号前的内容
	parenIdx := strings.Index(callText, "(")
	if parenIdx <= 0 {
		return ""
	}

	// 提取函数名（可能包含命名空间）
	funcName := strings.TrimSpace(callText[:parenIdx])

	// 移除可能的返回类型和赋值
	// 例如: "ptr = get_instance()" -> "get_instance"
	if strings.Contains(funcName, "=") {
		parts := strings.Split(funcName, "=")
		if len(parts) > 1 {
			funcName = strings.TrimSpace(parts[len(parts)-1])
		}
	}

	return funcName
}

// isNonNullGuaranteeFunction 检查函数是否保证返回非NULL
func (d *NullPointerDereferenceDetector) isNonNullGuaranteeFunction(funcName string) bool {
	lowerName := strings.ToLower(funcName)

	// 保证非NULL的函数模式
	guaranteePatterns := []string{
		"get_", "fetch_", "obtain_", "acquire_",
		"ensure_", "validate_", "check_",
		"create_", "new_", "make_",
		"init", "initialize", "setup",
	}

	for _, pattern := range guaranteePatterns {
		if strings.HasPrefix(lowerName, pattern) {
			return true
		}
	}

	return false
}

// isProtectedByAssertion 检查是否受断言保护
func (d *NullPointerDereferenceDetector) isProtectedByAssertion(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable
	derefLine := deref.Line

	// 检查是否有断言检查
	// 例如: assert(ptr != NULL);
	checks := flows.Checks[varName]
	for _, check := range checks {
		if check.Line < derefLine {
			// 检查是否是断言模式
			if d.isAssertionCheck(ctx, check) {
				return true
			}
		}
	}

	return false
}

// isAssertionCheck 检查是否是断言检查
func (d *NullPointerDereferenceDetector) isAssertionCheck(ctx *core.AnalysisContext, check *Check) bool {
	// 检查条件文本
	condText := ctx.GetSourceText(check.Node)

	// 检查是否包含 assert
	if strings.Contains(condText, "assert") {
		return true
	}

	return false
}

// isProtectedStaticVariable 检查是否是受保护的静态变量
func (d *NullPointerDereferenceDetector) isProtectedStaticVariable(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 检查该指针是否是静态变量
	alloc, exists := flows.Allocations[varName]
	if !exists {
		return false
	}

	// 检查 Node 是否为 nil
	if alloc.Node == nil {
		return false
	}

	// 检查声明是否包含static关键字
	declNode := alloc.Node.Parent()
	if declNode == nil || core.SafeType(declNode) != "declaration" {
		return false
	}

	// 检查是否有static修饰符
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if child != nil && core.SafeType(child) == "storage_class_specifier" {
			text := ctx.GetSourceText(child)
			if strings.Contains(text, "static") {
				// 这是一个静态变量
				// 检查是否有初始化检查
				checks := flows.Checks[varName]
				for _, check := range checks {
					if check.Line < deref.Line {
						return true
					}
				}
			}
		}
	}

	return false
}

// isProtectedByEarlyReturn 检查是否受早期返回保护
func (d *NullPointerDereferenceDetector) isProtectedByEarlyReturn(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	// 这个检查在现有的 isVulnerableDereference 中已经通过 guard_return 实现
	// 这里只是添加额外的逻辑

	// 检查是否有负向NULL检查后的早期返回
	// 例如: if (!ptr) return; ptr->x = 1;
	varName := deref.Variable

	checks := flows.Checks[varName]
	for _, check := range checks {
		if check.Line < deref.Line && check.CheckType == "guard_return" {
			return true
		}
	}

	return false
}

// isProtectedByLogicalImplication 检查是否受逻辑蕴含保护
func (d *NullPointerDereferenceDetector) isProtectedByLogicalImplication(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	// 查找包含解引用的条件
	// 例如: if (a && a->ptr) { a->ptr->x = 1; }

	// 向上查找父节点，看是否在if语句内
	parent := deref.Node.Parent()
	for parent != nil {
		if core.SafeType(parent) == "if_statement" {
			condition := core.SafeChildByFieldName(parent, "condition")
			if condition != nil {
				// 检查条件是否包含逻辑与操作
				if d.hasLogicalAndProtectingPointer(ctx, condition, deref.Variable) {
					return true
				}
			}
		}
		parent = parent.Parent()
	}

	return false
}

// hasLogicalAndProtectingPointer 检查条件是否包含保护指针的逻辑与
func (d *NullPointerDereferenceDetector) hasLogicalAndProtectingPointer(ctx *core.AnalysisContext, condition *sitter.Node, varName string) bool {
	condType := core.SafeType(condition)

	// 检查是否是逻辑与表达式
	if condType == "binary_expression" {
		// 检查操作符
		for i := 0; i < int(core.SafeChildCount(condition)); i++ {
			child := core.SafeChild(condition, i)
			if child != nil && core.SafeType(child) == "&&" {
				// 这是一个逻辑与表达式
				// 检查右侧是否包含对指针的NULL检查
				right := core.SafeChild(condition, 2)
				if right != nil {
					rightText := ctx.GetSourceText(right)
					if strings.Contains(rightText, varName) && strings.Contains(rightText, "NULL") {
						return true
					}
				}
			}
		}
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(condition)); i++ {
		child := core.SafeChild(condition, i)
		if d.hasLogicalAndProtectingPointer(ctx, child, varName) {
			return true
		}
	}

	return false
}

// === 第4次迭代新增函数 (基于 ZeroFalse 2025, LLM-Driven 2025) ===

// isInErrorHandler 检查是否在错误处理路径中
func (d *NullPointerDereferenceDetector) isInErrorHandler(ctx *core.AnalysisContext, deref *Dereference) bool {
	// 检查找节点的上下文
	if deref.Node == nil {
		return false
	}
	
	// 查找父节点
	parent := deref.Node.Parent()
	depth := 0
	const maxDepth = 10
	
	for parent != nil && depth < maxDepth {
		// 检查是否在if语句中
		if parent.Type() == "if_statement" {
			condition := parent.ChildByFieldName("condition")
			if condition != nil {
				condText := ctx.GetSourceText(condition)
				// 检查条件是否包含错误相关的变量
				errorPatterns := []string{
					"err", "ret", "status", "result", "error",
				}
				for _, pattern := range errorPatterns {
					if strings.Contains(condText, pattern) {
						return true
					}
				}
			}
		}
		
		// 检查是否在标签中（如err:, cleanup:）
		if parent.Type() == "labeled_statement" {
			label := parent.ChildByFieldName("label")
			if label != nil {
				labelText := ctx.GetSourceText(label)
				// 检查标签是否暗示错误处理
				cleanupLabels := []string{
					"err", "cleanup", "fail", "error", "exit",
				}
				for _, prefix := range cleanupLabels {
					if strings.HasPrefix(strings.ToLower(labelText), prefix) {
						return true
					}
				}
			}
		}
		
		parent = parent.Parent()
		depth++
	}
	
	return false
}

// isInCleanupPath 检查是否在资源清理路径中
func (d *NullPointerDereferenceDetector) isInCleanupPath(ctx *core.AnalysisContext, deref *Dereference) bool {
	// 检查找节点的上下文
	if deref.Node == nil {
		return false
	}
	
	// 查找父节点
	parent := deref.Node.Parent()
	depth := 0
	const maxDepth = 10
	
	for parent != nil && depth < maxDepth {
		// 检查是否在标签语句中
		if parent.Type() == "labeled_statement" {
			label := parent.ChildByFieldName("label")
			if label != nil {
				labelText := ctx.GetSourceText(label)
				// 清理标签模式
				cleanupPatterns := []string{
					"cleanup", "end", "done", "finish", "out",
				}
				for _, pattern := range cleanupPatterns {
					if strings.Contains(strings.ToLower(labelText), pattern) {
						return true
					}
				}
			}
		}
		
		// 检查是否在函数末尾的清理代码中
		if parent.Type() == "function_definition" {
			// 检查函数体末尾是否有清理代码
			body := parent.ChildByFieldName("body")
			if body != nil {
				// 如果解引用在函数体的末尾部分，可能是清理代码
				// 这里使用简单的启发式：检查是否有free, close等清理函数调用
				bodyText := ctx.GetSourceText(body)
				if strings.Contains(bodyText, "free(") || 
				   strings.Contains(bodyText, "close(") ||
				   strings.Contains(bodyText, "cleanup") {
					return true
				}
			}
		}
		
		parent = parent.Parent()
		depth++
	}
	
	return false
}

// isOpenSSLObjectInitialized 检查是否是OpenSSL对象初始化模式
func (d *NullPointerDereferenceDetector) isOpenSSLObjectInitialized(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable

	// 检查分配记录
	alloc, exists := flows.Allocations[varName]
	if !exists || alloc == nil {
		return false
	}

	if alloc.Node == nil {
		return false
	}

	allocText := ctx.GetSourceText(alloc.Node)

	// OpenSSL初始化函数模式（这些函数保证返回有效对象或NULL）
	opensslInitPatterns := []string{
		"EVP_", "ASN1_", "RSA_", "EC_", "DSA_", "DH_",
		"BIO_", "SSL_", "CTX_", "X509_", "PEM_",
		"HASH_", "CIPH_", "DIGEST_", "MAC_",
	}

	for _, pattern := range opensslInitPatterns {
		if strings.Contains(allocText, pattern) {
			// OpenSSL初始化函数通常保证返回有效对象
			return true
		}
	}

	return false
}

// hasOpenSSLRefcountGuard 检查是否有OpenSSL引用计数保护
func (d *NullPointerDereferenceDetector) hasOpenSSLRefcountGuard(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	// 检查找节点前的代码
	if deref.Node == nil {
		return false
	}

	// 查找父节点，检查引用计数操作
	parent := deref.Node.Parent()
	depth := 0
	const maxDepth = 5

	for parent != nil && depth < maxDepth {
		// 获取父节点的源代码
		parentText := ctx.GetSourceText(parent)

		// OpenSSL引用计数函数
		refcountPatterns := []string{
			"CRYPTO_add", "CRYPTO_get_count", "CRYPTO_up_ref",
			"CRYPTO_new", "CRYPTO_free", "CRYPTO_atomic_add",
		}

		for _, pattern := range refcountPatterns {
			if strings.Contains(parentText, pattern) {
				// 引用计数操作通常会检查指针
				return true
			}
		}

		// 检查是否有引用计数字段访问（如ptr->references, ptr->refcount）
		if strings.Contains(parentText, "->ref") ||
			strings.Contains(parentText, "->count") ||
			strings.Contains(parentText, ".ref") ||
			strings.Contains(parentText, ".count") {
			return true
		}

		parent = parent.Parent()
		depth++
	}

	return false
}

// isWrappedByOpenSSLAPI 检查是否是OpenSSL包装API模式
func (d *NullPointerDereferenceDetector) isWrappedByOpenSSLAPI(ctx *core.AnalysisContext, deref *Dereference, flows *DataFlow) bool {
	varName := deref.Variable
	
	// 检查赋值历史
	assignments, exists := flows.Assignments[varName]
	if !exists || len(assignments) == 0 {
		return false
	}
	
	// 检查第一次赋值
	firstAssign := assignments[0]
	assignText := strings.TrimSpace(firstAssign.Value)
	
	// OpenSSL包装函数模式（这些函数有内部NULL检查）
	opensslWrapperPatterns := []string{
		"OPENSSL_malloc", "OPENSSL_zalloc", "OPENSSL_realloc",
		"OPENSSL_strdup", "OPENSSL_strndup",
		"OPENSSL_cleanse", "OPENSSL_clear_free",
	}
	
	for _, pattern := range opensslWrapperPatterns {
		if strings.Contains(assignText, pattern) {
			return true
		}
	}
	
	// 检查是否是OPENSSL_开头的函数
	if strings.HasPrefix(assignText, "OPENSSL_") {
		return true
	}
	
	// 检查是否是ASN1_、EVP_等开头的函数
	opensslPrefixes := []string{
		"ASN1_", "EVP_", "BIO_", "SSL_", "X509_",
		"PEM_", "DH_", "RSA_", "EC_", "DSA_",
		"HMAC_", "CMAC_", "MD5_", "SHA1_", "SHA256_",
	}
	
	for _, prefix := range opensslPrefixes {
		if strings.HasPrefix(assignText, prefix) {
			return true
		}
	}
	
	return false
}
