package detectors

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// BufferOverflowDetector 缓冲区溢出检测器
// 使用污点分析和 Z3 约束求解进行精确分析
// 阶段1改进：长度敏感分析 - 追踪字符串长度区间
// 阶段2改进：CFG 路径敏感性分析 - 识别保护性检查
type BufferOverflowDetector struct {
	*core.BaseDetector
	z3Solver     core.Z3Solver
	bufferSizes  map[string]int64            // 缓冲区大小: varName -> size
	scopeBuffers map[string]map[string]int64 // 作用域感知: funcName -> varName -> size
	// 【阶段1新增】长度域分析
	lengthDomains map[string]*LengthInterval // 变量 -> 长度区间
	strlenCalls   map[string]string          // strlen(var) 调用追踪
	// 【阶段2新增】路径敏感性分析
	pathConditions map[string][]PathCondition // 节点ID -> 路径条件列表
	// 【阶段2新增-P1】动态分配跟踪
	dynamicAllocations map[string]*DynamicAllocation // 变量名 -> 动态分配信息
	allocSizeExprs     map[string]string             // 变量名 -> 分配大小表达式
	// 【阶段2新增-P2】跨过程分析（参数保护传递）
	paramProtections map[string][]ParamProtection // 函数名 -> 参数保护列表
	mu               sync.RWMutex                 // 保护 map 的并发访问
}

// LengthInterval 长度区间抽象值
type LengthInterval struct {
	Min       int64 // 最小可能长度
	Max       int64 // 最大可能长度 (-1 = unknown/infinite)
	IsConst   bool  // 是否是常量字符串
	Value     int64 // 常量值
	IsTainted bool  // 是否来自不可信源
}

// PathCondition 路径条件
type PathCondition struct {
	Node       *sitter.Node // 条件节点
	Variable   string       // 涉及的变量
	Operation  string       // 操作符: "<", ">", "<=", ">=", "==", "!=", "&&", "||"
	Value      int64        // 比较值 (如果是常量)
	Expression string       // 完整表达式文本
	IsSafe     bool         // 是否为保护性条件
	Negated    bool         // 条件是否取反 (在 else 分支中)
	Line       int          // 行号
}

// ProtectionPattern 保护模式
type ProtectionPattern struct {
	Pattern     string // 正则表达式模式
	IsSafeCheck bool   // 是否为安全检查
	Description string // 描述
}

// DynamicAllocation 动态分配信息
type DynamicAllocation struct {
	VarName     string // 分配的变量名
	AllocType   string // 分配类型: "malloc", "calloc", "realloc"
	SizeExpr    string // 分配大小表达式
	SizeVar     string // 大小变量（如果有）
	LineNumber  int    // 分配位置行号
	FuncName    string // 所在函数名
	IsSizeOfSrc bool   // 分配大小是否基于源大小（如 malloc(strlen(src)+1)）
}

// ParamProtection 参数保护信息（P2跨过程分析）
type ParamProtection struct {
	FuncName   string        // 函数名
	ParamIndex int           // 参数索引
	Protection PathCondition // 保护条件
	CallSite   string        // 调用点位置
	ParamName  string        // 参数名（如果有）
}

// BufferOverflowPathConstraint 路径约束（P3符号执行）
type BufferOverflowPathConstraint struct {
	Variable   string // 约束变量
	Operator   string // 约束操作符: "<", ">", "<=", ">=", "==", "!=", "&&", "||"
	Value      int64  // 约束值（常量）
	Expression string // 完整表达式
	IsConjunct bool   // 是否为合取约束（&&）
	IsDisjunct bool   // 是否为析取约束（||）
	Line       int    // 约束位置
}

// SymbolicState 符号状态（P3符号执行）
type SymbolicState struct {
	Constraints []BufferOverflowPathConstraint // 路径约束集合
	Variables   map[string]int64               // 变量到符号值的映射
	IsFeasible  bool                           // 路径是否可行
	Reason      string                         // 不可行原因
}

// 已知的保护模式
var protectionPatterns = []ProtectionPattern{
	{`strlen\s*\(\s*(\w+)\s*\)\s*[<]=\s*sizeof\s*\(\s*(\w+)\s*\)`, true, "strlen 保护"},
	{`sizeof\s*\(\s*(\w+)\s*\)\s*[>]=\s*strlen\s*\(\s*(\w+)\s*\)`, true, "sizeof 保护"},
	{`(\w+)\s*[<]=\s*\d+`, true, "常量上界检查"},
	{`(\w+)\s*[<]\s*sizeof\s*\(\s*(\w+)\s*\)`, true, "sizeof 比较"},
	{`sizeof\s*\(\s*\w+\s*\)\s*-\s*1\s*[>]=\s*strlen`, true, "预留 null 终止符"},
}

// 危险函数列表
var dangerousFunctions = map[string]DangerousFuncInfo{
	// 无边界检查的字符串函数
	"strcpy":   {Category: "string_copy", DstArg: 0, SrcArg: 1, NoBoundsCheck: true},
	"strcat":   {Category: "string_concat", DstArg: 0, SrcArg: 1, NoBoundsCheck: true},
	"sprintf":  {Category: "format_string", DstArg: 0, FmtArg: 1, NoBoundsCheck: true},
	"vsprintf": {Category: "format_string", DstArg: 0, FmtArg: 1, NoBoundsCheck: true},
	"gets":     {Category: "input", DstArg: 0, NoBoundsCheck: true, AlwaysDangerous: true},

	// 可能危险的函数（需要检查大小参数）
	"strncpy":  {Category: "string_copy", DstArg: 0, SrcArg: 1, SizeArg: 2, NoBoundsCheck: false},
	"strncat":  {Category: "string_concat", DstArg: 0, SrcArg: 1, SizeArg: 2, NoBoundsCheck: false},
	"snprintf": {Category: "format_string", DstArg: 0, SizeArg: 1, FmtArg: 2, NoBoundsCheck: false},
	"memcpy":   {Category: "memory_copy", DstArg: 0, SrcArg: 1, SizeArg: 2, NoBoundsCheck: false},
	"memmove":  {Category: "memory_copy", DstArg: 0, SrcArg: 1, SizeArg: 2, NoBoundsCheck: false},

	// 输入函数
	"scanf":  {Category: "input", FmtArg: 0, NoBoundsCheck: true},
	"fscanf": {Category: "input", FmtArg: 1, NoBoundsCheck: true},
	"sscanf": {Category: "input", SrcArg: 0, FmtArg: 1, NoBoundsCheck: true},
}

// DangerousFuncInfo 危险函数信息
type DangerousFuncInfo struct {
	Category        string // 函数类别
	DstArg          int    // 目标缓冲区参数索引
	SrcArg          int    // 源数据参数索引
	SizeArg         int    // 大小参数索引
	FmtArg          int    // 格式字符串参数索引
	NoBoundsCheck   bool   // 是否无边界检查
	AlwaysDangerous bool   // 是否始终危险（如 gets）
}

// NewBufferOverflowDetector 创建新的缓冲区溢出检测器
func NewBufferOverflowDetector() *BufferOverflowDetector {
	solver, _ := core.CreateZ3Solver()

	return &BufferOverflowDetector{
		BaseDetector: core.NewBaseDetector(
			"buffer_overflow",
			"Detects buffer overflow vulnerabilities (CWE-120) using taint analysis and Z3",
		),
		z3Solver:           solver,
		bufferSizes:        make(map[string]int64),
		scopeBuffers:       make(map[string]map[string]int64),
		lengthDomains:      make(map[string]*LengthInterval),    // 阶段1新增
		strlenCalls:        make(map[string]string),             // 阶段1新增
		pathConditions:     make(map[string][]PathCondition),    // 阶段2新增
		dynamicAllocations: make(map[string]*DynamicAllocation), // 阶段2-P1新增
		allocSizeExprs:     make(map[string]string),             // 阶段2-P1新增
		paramProtections:   make(map[string][]ParamProtection),  // 阶段2-P2新增
	}
}

// Name 返回检测器名称
func (d *BufferOverflowDetector) Name() string {
	return "Buffer Overflow Detector"
}

// Description 返回检测器描述
func (d *BufferOverflowDetector) Description() string {
	return "Detects potential buffer overflow vulnerabilities using taint analysis and Z3 constraint solving"
}

// Run 执行检测
func (d *BufferOverflowDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	startTime := time.Now()

	// 1. 初始化 Z3 求解器
	z3Initialized := false
	if d.z3Solver == nil {
		solver, err := core.CreateZ3Solver()
		if err == nil && solver != nil {
			d.z3Solver = solver
			z3Initialized = true
		}
	}

	// 2. 初始化污点分析引擎（如果尚未初始化）
	ctx.InitTaintEngine()

	// 3. 执行跨函数污点传播（在检测之前）
	// 这确保 argv -> arcname 的污点能够被正确追踪
	if err := ctx.RunCrossFunctionTaintPropagation(); err != nil {
		// 跨函数污点传播失败不是致命错误，继续执行
		fmt.Printf("[Warning] Cross-function taint propagation failed: %v\n", err)
	}

	// 4. 收集所有缓冲区声明及其大小
	d.collectBufferSizes(ctx)

	// 5. 【阶段1新增】收集字符串长度域信息
	d.collectLengthDomains(ctx)

	// 6. 【阶段2新增】收集路径条件信息
	d.collectPathConditions(ctx)

	// 7. 【阶段2-P1新增】收集动态分配信息
	d.collectDynamicAllocations(ctx)

	// 8. 【阶段2-P2新增】收集参数保护信息（跨过程分析）
	d.collectParamProtections(ctx)

	// 9. 查找所有危险函数调用
	dangerousCalls, err := d.findDangerousCalls(ctx)
	if err != nil {
		if z3Initialized && d.z3Solver != nil {
			d.z3Solver.Close()
		}
		return nil, err
	}

	// 10. 分析每个危险调用
	for _, call := range dangerousCalls {
		if vuln := d.analyzeCall(ctx, call); vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	// 11. 【新增】循环边界分析 - 检测 Off-by-one 错误
	loopVulns := d.analyzeLoopBounds(ctx)
	vulns = append(vulns, loopVulns...)

	// 12. 清理资源（仅当我们初始化时）
	if z3Initialized && d.z3Solver != nil {
		d.z3Solver.Close()
		d.z3Solver = nil // 重置为 nil，避免重复关闭
	}

	_ = time.Since(startTime) // 保留 startTime 变量避免未使用警告
	return vulns, nil
}

// collectBufferSizes 收集缓冲区大小信息
func (d *BufferOverflowDetector) collectBufferSizes(ctx *core.AnalysisContext) {
	// 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, err := ctx.Query(funcQuery)
	if err != nil {
		return
	}

	for _, funcMatch := range funcMatches {
		funcName := d.extractFuncName(ctx, funcMatch.Node)
		if funcName == "" {
			continue
		}

		// 使用锁保护 scopeBuffers 的并发访问
		d.mu.Lock()
		d.scopeBuffers[funcName] = make(map[string]int64)
		d.mu.Unlock()

		d.collectBuffersInScope(ctx, funcMatch.Node, funcName)
	}
}

// extractFuncName 提取函数名
func (d *BufferOverflowDetector) extractFuncName(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
	// *** 修复 ***: 使用 context 的 ExtractFunctionNameFromDef 方法
	// 该方法已经正确处理了 pointer_declarator 等情况
	if ctx != nil && funcNode != nil {
		return ctx.ExtractFunctionNameFromDef(funcNode)
	}

	// 回退到旧的逻辑（保留以兼容）
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

// collectBuffersInScope 在函数作用域内收集缓冲区
func (d *BufferOverflowDetector) collectBuffersInScope(ctx *core.AnalysisContext, node *sitter.Node, funcName string) {
	if node == nil {
		return
	}

	// 处理声明: char buffer[10]; 或 char *buffer = malloc(100);
	if core.SafeType(node) == "declaration" {
		d.extractArrayDeclaration(ctx, node, funcName)
		d.extractMallocDeclaration(ctx, node, funcName)
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.collectBuffersInScope(ctx, core.SafeChild(node, i), funcName)
	}
}

// extractArrayDeclaration 提取数组声明信息
func (d *BufferOverflowDetector) extractArrayDeclaration(ctx *core.AnalysisContext, declNode *sitter.Node, funcName string) {
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)

		// 查找 array_declarator: buffer[10]
		if core.SafeType(child) == "array_declarator" {
			varName, size := d.parseArrayDeclarator(ctx, child)
			if varName != "" && size > 0 {
				// 【修复】使用锁保护 scopeBuffers 的并发访问
				d.mu.Lock()
				if scope, ok := d.scopeBuffers[funcName]; ok {
					scope[varName] = size
				}
				d.bufferSizes[varName] = size
				d.mu.Unlock()
			}
		}

		// 查找 init_declarator 中的 array_declarator
		if core.SafeType(child) == "init_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "array_declarator" {
					varName, size := d.parseArrayDeclarator(ctx, subChild)
					if varName != "" && size > 0 {
						// 【修复】使用锁保护 scopeBuffers 的并发访问
						d.mu.Lock()
						if scope, ok := d.scopeBuffers[funcName]; ok {
							scope[varName] = size
						}
						d.bufferSizes[varName] = size
						d.mu.Unlock()
					}
				}
			}
		}
	}
}

// parseArrayDeclarator 解析数组声明器
func (d *BufferOverflowDetector) parseArrayDeclarator(ctx *core.AnalysisContext, arrayDecl *sitter.Node) (string, int64) {
	var varName string
	var size int64

	// 【阶段1改进】支持更多 AST 结构类型
	// tree-sitter 的 array_declarator 可能有不同的子节点结构
	for i := 0; i < int(core.SafeChildCount(arrayDecl)); i++ {
		child := core.SafeChild(arrayDecl, i)
		if child == nil {
			continue
		}
		childType := core.SafeType(child)

		// 查找标识符（变量名）
		if childType == "identifier" {
			varName = ctx.GetSourceText(child)
		} else if childType == "number_literal" {
			// 解析数组大小（如 1024）
			if val, err := strconv.ParseInt(ctx.GetSourceText(child), 0, 64); err == nil {
				size = val
			}
		} else if childType == "subscript_expression" {
			// 处理更复杂的数组大小表达式
			// subscript_expression 可能包含嵌套的 number_literal
			size = d.extractSizeFromSubscript(ctx, child)
		} else if childType == "field_expression" || childType == "pointer_declarator" {
			// 这些节点类型可能包含 identifier 或 size 信息
			// 递归查找
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				subType := core.SafeType(subChild)
				if subType == "identifier" && varName == "" {
					varName = ctx.GetSourceText(subChild)
				} else if subType == "number_literal" && size == 0 {
					if val, err := strconv.ParseInt(ctx.GetSourceText(subChild), 0, 64); err == nil {
						size = val
					}
				}
			}
		}
	}

	return varName, size
}

// extractSizeFromSubscript 从 subscript_expression 中提取大小
func (d *BufferOverflowDetector) extractSizeFromSubscript(ctx *core.AnalysisContext, subscript *sitter.Node) int64 {
	// 递归查找 number_literal
	for i := 0; i < int(core.SafeChildCount(subscript)); i++ {
		child := core.SafeChild(subscript, i)
		if child == nil {
			continue
		}

		childType := core.SafeType(child)
		if childType == "number_literal" {
			if val, err := strconv.ParseInt(ctx.GetSourceText(child), 0, 64); err == nil {
				return val
			}
		}

		// 递归检查子节点
		if subSize := d.extractSizeFromSubscript(ctx, child); subSize > 0 {
			return subSize
		}
	}
	return 0
}

// extractMallocDeclaration 提取 malloc/calloc 分配的缓冲区大小
// 例如: char *buffer = (char*)malloc(100);
func (d *BufferOverflowDetector) extractMallocDeclaration(ctx *core.AnalysisContext, declNode *sitter.Node, funcName string) {
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)

		if core.SafeType(child) == "init_declarator" {
			varName, size := d.parseMallocInitDeclarator(ctx, child)
			if varName != "" && size > 0 {
				// 【修复】使用锁保护 scopeBuffers 的并发访问
				d.mu.Lock()
				if scope, ok := d.scopeBuffers[funcName]; ok {
					scope[varName] = size
				}
				d.mu.Unlock()
			}
		}
	}
}

// parseMallocInitDeclarator 解析包含 malloc 的初始化声明
func (d *BufferOverflowDetector) parseMallocInitDeclarator(ctx *core.AnalysisContext, initDecl *sitter.Node) (string, int64) {
	var varName string
	var size int64

	for i := 0; i < int(core.SafeChildCount(initDecl)); i++ {
		child := core.SafeChild(initDecl, i)

		// 获取变量名 (pointer_declarator: *buffer)
		if core.SafeType(child) == "pointer_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "identifier" {
					varName = ctx.GetSourceText(subChild)
				}
			}
		}

		// 获取 malloc 大小 (cast_expression 或直接 call_expression)
		if core.SafeType(child) == "cast_expression" || core.SafeType(child) == "call_expression" {
			size = d.extractMallocSize(ctx, child)
		}
	}

	return varName, size
}

// extractMallocSize 从表达式中提取 malloc/calloc 的分配大小
func (d *BufferOverflowDetector) extractMallocSize(ctx *core.AnalysisContext, node *sitter.Node) int64 {
	if node == nil {
		return 0
	}

	// 处理 call_expression: malloc(100)
	if core.SafeType(node) == "call_expression" {
		funcName := ""
		var args []*sitter.Node

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if core.SafeType(child) == "identifier" {
				funcName = ctx.GetSourceText(child)
			} else if core.SafeType(child) == "argument_list" {
				for j := 0; j < int(core.SafeChildCount(child)); j++ {
					arg := core.SafeChild(child, j)
					if core.SafeType(arg) != "(" && core.SafeType(arg) != ")" && core.SafeType(arg) != "," {
						args = append(args, arg)
					}
				}
			}
		}

		// malloc(size) - 单参数
		if funcName == "malloc" && len(args) >= 1 {
			return d.evaluateExpression(ctx, args[0])
		}

		// calloc(count, size) - count * size
		if funcName == "calloc" && len(args) >= 2 {
			count := d.evaluateExpression(ctx, args[0])
			elemSize := d.evaluateExpression(ctx, args[1])
			if count > 0 && elemSize > 0 {
				return count * elemSize
			}
		}

		// realloc(ptr, size) - 第二个参数是新大小
		if funcName == "realloc" && len(args) >= 2 {
			return d.evaluateExpression(ctx, args[1])
		}
	}

	// 处理 cast_expression: (char*)malloc(100)
	if core.SafeType(node) == "cast_expression" {
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if core.SafeType(child) == "call_expression" {
				return d.extractMallocSize(ctx, child)
			}
		}
	}

	return 0
}

// evaluateExpression 计算表达式的值（支持 sizeof、字面量、简单乘法）
func (d *BufferOverflowDetector) evaluateExpression(ctx *core.AnalysisContext, node *sitter.Node) int64 {
	if node == nil {
		return 0
	}

	// 数字字面量
	if core.SafeType(node) == "number_literal" {
		if val, err := strconv.ParseInt(ctx.GetSourceText(node), 0, 64); err == nil {
			return val
		}
	}

	// sizeof 表达式
	if core.SafeType(node) == "sizeof_expression" {
		return d.evaluateSizeof(ctx, node)
	}

	// 二元表达式（乘法）
	if core.SafeType(node) == "binary_expression" {
		text := ctx.GetSourceText(node)
		if strings.Contains(text, "*") && core.SafeChildCount(node) >= 3 {
			left := d.evaluateExpression(ctx, core.SafeChild(node, 0))
			right := d.evaluateExpression(ctx, core.SafeChild(node, 2))
			if left > 0 && right > 0 {
				return left * right
			}
		}
	}

	return 0
}

// evaluateSizeof 计算 sizeof 表达式的值
func (d *BufferOverflowDetector) evaluateSizeof(ctx *core.AnalysisContext, sizeofNode *sitter.Node) int64 {
	text := ctx.GetSourceText(sizeofNode)

	// 基本类型
	if strings.Contains(text, "int") && !strings.Contains(text, "uint") {
		return 4
	}
	if strings.Contains(text, "char") {
		return 1
	}
	if strings.Contains(text, "long") {
		return 8
	}
	if strings.Contains(text, "double") {
		return 8
	}
	if strings.Contains(text, "float") {
		return 4
	}
	if strings.Contains(text, "short") {
		return 2
	}

	return 0
}

// findDangerousCalls 查找所有危险函数调用
func (d *BufferOverflowDetector) findDangerousCalls(ctx *core.AnalysisContext) ([]DangerousCall, error) {
	query := `(call_expression) @call`
	matches, err := ctx.Query(query)
	if err != nil {
		return nil, err
	}

	var calls []DangerousCall

	for _, match := range matches {
		funcName := d.getCallFunctionName(ctx, match.Node)
		if info, isDangerous := dangerousFunctions[funcName]; isDangerous {
			calls = append(calls, DangerousCall{
				Node:     match.Node,
				FuncName: funcName,
				Info:     info,
			})
		}
	}

	return calls, nil
}

// DangerousCall 危险函数调用
type DangerousCall struct {
	Node     *sitter.Node
	FuncName string
	Info     DangerousFuncInfo
}

// getCallFunctionName 获取函数调用的函数名
func (d *BufferOverflowDetector) getCallFunctionName(ctx *core.AnalysisContext, callNode *sitter.Node) string {
	for i := 0; i < int(core.SafeChildCount(callNode)); i++ {
		child := core.SafeChild(callNode, i)
		if core.SafeType(child) == "identifier" {
			return strings.TrimSpace(ctx.GetSourceText(child))
		}
	}
	return ""
}

// analyzeCall 分析单个危险函数调用
func (d *BufferOverflowDetector) analyzeCall(ctx *core.AnalysisContext, call DangerousCall) *core.DetectorVulnerability {
	line := int(call.Node.StartPoint().Row) + 1
	funcName := d.getFunctionForNode(ctx, call.Node)

	// 获取参数列表
	args := d.getCallArguments(ctx, call.Node)

	// 始终危险的函数（如 gets）
	if call.Info.AlwaysDangerous {
		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE120,
			fmt.Sprintf("Use of dangerous function '%s' at line %d (always unsafe, use fgets instead)", call.FuncName, line),
			call.Node,
			core.ConfidenceHigh,
			core.SeverityCritical,
		)
		return &vuln
	}

	// 无边界检查的函数
	if call.Info.NoBoundsCheck {
		return d.analyzeNoBoundsCheckCall(ctx, call, args, funcName, line)
	}

	// 有大小参数的函数，检查大小是否正确
	return d.analyzeBoundsCheckCall(ctx, call, args, funcName, line)
}

// getCallArguments 获取函数调用的参数
func (d *BufferOverflowDetector) getCallArguments(ctx *core.AnalysisContext, callNode *sitter.Node) []*sitter.Node {
	var args []*sitter.Node

	for i := 0; i < int(core.SafeChildCount(callNode)); i++ {
		child := core.SafeChild(callNode, i)
		if core.SafeType(child) == "argument_list" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				arg := core.SafeChild(child, j)
				// 跳过括号和逗号
				if core.SafeType(arg) != "(" && core.SafeType(arg) != ")" && core.SafeType(arg) != "," {
					args = append(args, arg)
				}
			}
			break
		}
	}

	return args
}

// analyzeNoBoundsCheckCall 分析无边界检查的函数调用
func (d *BufferOverflowDetector) analyzeNoBoundsCheckCall(ctx *core.AnalysisContext, call DangerousCall, args []*sitter.Node, funcName string, line int) *core.DetectorVulnerability {
	if len(args) < 2 {
		return nil
	}

	// 获取目标缓冲区
	dstArg := args[call.Info.DstArg]
	dstName := strings.TrimSpace(ctx.GetSourceText(dstArg))
	dstSize := d.getBufferSize(dstName, funcName)

	// 【阶段2改进】首先检查路径保护
	var srcName string
	if call.Info.SrcArg >= 0 && len(args) > call.Info.SrcArg {
		srcName = ctx.GetSourceText(args[call.Info.SrcArg])
	}

	isProtected, _ := d.checkPathProtection(ctx, call.Node, dstName, srcName)
	if isProtected {
		// 有路径保护，不报告漏洞
		return nil
	}

	// 【阶段2-P1新增】检查是否为动态分配的安全使用
	if safeDynamic, _ := d.isDynamicAllocatedSafe(ctx, dstName, srcName); safeDynamic {
		// 动态分配基于源大小，是安全的
		return nil
	}

	// 对于 strcpy/strcat，使用增强的 Z3 分析
	if call.Info.Category == "string_copy" || call.Info.Category == "string_concat" {
		srcArg := args[call.Info.SrcArg]

		// 【阶段1改进】首先尝试长度域分析
		if dstSize > 0 {
			srcInterval := d.analyzeStringLength(ctx, srcArg)
			srcName := ctx.GetSourceText(srcArg)

			// 检查是否必定溢出
			if certain, reason := d.isCertainOverflow(dstSize, srcInterval, dstName, srcName); certain {
				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE120,
					reason+fmt.Sprintf(" at line %d", line),
					call.Node,
					core.ConfidenceHigh,
					core.SeverityCritical,
				)
				return &vuln
			}

			// 检查是否必定安全
			if safe, _ := d.isCertainSafe(dstSize, srcInterval, dstName, srcName); safe {
				// 必定安全，不报告
				return nil
			}

			// 长度域分析无法确定，回退到原有Z3分析
			isSafe, reason, srcSize := d.analyzeBufferSafetyWithZ3(dstName, dstSize, srcArg, ctx, funcName)

			// 根据分析结果生成不同级别的报告
			if dstSize > 0 && srcSize > 0 {
				// 已知大小的溢出 - 关键级别
				if strings.Contains(reason, "overflow") {
					vuln := d.BaseDetector.CreateVulnerability(
						core.CWE120,
						fmt.Sprintf("%s at line %d", reason, line),
						call.Node,
						core.ConfidenceHigh,
						core.SeverityCritical,
					)
					return &vuln
				}

				// 已知大小且安全 - Z3 证明安全，不报告漏洞
				if isSafe {
					// 安全操作，Z3 已验证，不报告
					return nil
				}
			}

			// 如果目标缓冲区大小已知但源大小未知
			if dstSize > 0 {
				// *** 改进 ***: 使用函数作用域的污点检查，而不是全局污点检查
				// 获取当前函数名
				currentFuncName := d.getFunctionForNode(ctx, call.Node)

				// 检查源是否来自用户输入（污点分析）
				isTainted := false
				if ctx.Taint != nil && currentFuncName != "" {
					engine := ctx.Taint.(*core.MemoryTaintEngine)
					if core.SafeType(srcArg) == "identifier" {
						isTainted = engine.IsIdentifierTaintedInFunction(srcArg, currentFuncName)
					} else {
						// 对于非 identifier 类型，使用全局污点检查
						isTainted = ctx.IsTainted(srcArg)
					}
				} else if ctx.Taint != nil {
					// 回退到全局污点检查
					isTainted = ctx.IsTainted(srcArg)
				}

				if isTainted {
					vuln := d.BaseDetector.CreateVulnerability(
						core.CWE120,
						fmt.Sprintf("Potential buffer overflow: %s() with tainted source to buffer '%s' (size %d) at line %d",
							call.FuncName, dstName, dstSize, line),
						call.Node,
						core.ConfidenceMedium,
						core.SeverityHigh,
					)
					return &vuln
				}

				// 有缓冲区大小信息但源大小无法静态确定
				if strings.Contains(reason, "unknown") {
					vuln := d.BaseDetector.CreateVulnerability(
						core.CWE120,
						fmt.Sprintf("%s at line %d", reason, line),
						call.Node,
						core.ConfidenceMedium,
						core.SeverityHigh,
					)
					return &vuln
				}
			}
		}

		// *** 改进：加强对函数参数源的污点检查 ***
		// 不再使用大缓冲区阈值，而是基于源的可信度进行分析

		// 1. 首先检查源字符串是否为字符串字面量（完全可信）
		srcArg = args[call.Info.SrcArg]
		if srcArg != nil && core.SafeType(srcArg) == "string_literal" {
			srcText := ctx.GetSourceText(srcArg)
			srcLen := int64(len(srcText) - 2) // 去除引号

			// 如果源是字符串字面量且长度已知
			if srcLen > 0 {
				// 如果知道目标缓冲区大小
				if dstSize > 0 {
					if srcLen < dstSize {
						// 源字符串比目标缓冲区小，安全
						return nil
					} else if srcLen >= dstSize {
						// 源字符串大于等于目标缓冲区，必定溢出
						reason := fmt.Sprintf("CERTAIN OVERFLOW: copying string of %d bytes to buffer '%s' of %d bytes",
							srcLen, dstName, dstSize)
						vuln := d.BaseDetector.CreateVulnerability(
							core.CWE120,
							reason+fmt.Sprintf(" at line %d", line),
							call.Node,
							core.ConfidenceHigh,
							core.SeverityCritical,
						)
						return &vuln
					}
				} else if srcLen < 64 {
					// 源字符串很短（<64字节），很可能是安全的
					return nil
				}
			}
		}

		// 2. 检查源是否为标识符（可能是函数参数、变量等）
		if srcArg != nil && core.SafeType(srcArg) == "identifier" {
			srcName := strings.TrimSpace(ctx.GetSourceText(srcArg))

			// *** 改进：使用函数作用域的污点检查 ***
			// 获取当前函数名
			currentFuncName := d.getFunctionForNode(ctx, call.Node)

			// 检查是否为函数参数（通过查找当前函数的参数列表）
			if d.isFunctionParameter(ctx, srcArg, srcName) {
				// 函数参数可能是 tainted 的，需要严格检查

				// *** 关键改进 ***：使用 IsIdentifierTaintedInFunction 检查污点
				// 这会检查：
				// 1. 节点级别的污点
				// 2. 全局变量名级别的污点
				// 3. 函数作用域的变量名污点（跨函数传播）
				isTainted := false
				if ctx.Taint != nil && currentFuncName != "" {
					engine := ctx.Taint.(*core.MemoryTaintEngine)
					isTainted = engine.IsIdentifierTaintedInFunction(srcArg, currentFuncName)
				}

				// 2a. 如果明确标记为 tainted，高风险
				if isTainted {
					vuln := d.BaseDetector.CreateVulnerability(
						core.CWE120,
						fmt.Sprintf("Potential buffer overflow: %s() with tainted parameter '%s' to buffer '%s' (size: %d bytes) - unbounded copy from untrusted source (function: %s)",
							call.FuncName, srcName, dstName, dstSize, currentFuncName),
						call.Node,
						core.ConfidenceHigh,
						core.SeverityHigh,
					)
					return &vuln
				}

				// 2b. 函数参数即使未明确标记为 tainted，也属于不可信源
				// 根据缓冲区大小调整置信度和严重度
				if dstSize > 0 {
					var confidence string
					var severity string

					if dstSize < 256 {
						// 小缓冲区 + 函数参数 = 高风险
						confidence = core.ConfidenceMedium
						severity = core.SeverityHigh
					} else if dstSize < 1024 {
						// 中等缓冲区 + 函数参数 = 中等风险
						confidence = core.ConfidenceLow
						severity = core.SeverityMedium
					} else {
						// 大缓冲区（>=1KB）+ 函数参数 = 低风险但仍需报告
						confidence = core.ConfidenceLow
						severity = core.SeverityMedium
					}

					vuln := d.BaseDetector.CreateVulnerability(
						core.CWE120,
						fmt.Sprintf("Potential buffer overflow: %s() with parameter '%s' to buffer '%s' (size: %d bytes) - cannot verify parameter size at compile time",
							call.FuncName, srcName, dstName, dstSize),
						call.Node,
						confidence,
						severity,
					)
					return &vuln
				}

				// 不知道缓冲区大小时，也报告
				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE120,
					fmt.Sprintf("Unsafe use of %s() with parameter '%s' to buffer '%s' - unbounded copy from function parameter",
						call.FuncName, srcName, dstName),
					call.Node,
					core.ConfidenceLow,
					core.SeverityMedium,
				)
				return &vuln
			}
		}

		// 3. 检查是否为结构体成员访问（可能有上下文保护）
		if strings.Contains(dstName, "->") || strings.Contains(dstName, ".") {
			// 结构体成员访问的strcpy通常有上下文保护
			// 保守策略：降低置信度和严重度
			if dstSize > 0 && dstSize < 256 {
				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE120,
					fmt.Sprintf("Unsafe use of %s() to struct member '%s' (size: %d bytes) - consider using bounds-checked function",
						call.FuncName, dstName, dstSize),
					call.Node,
					core.ConfidenceLow,
					core.SeverityMedium,
				)
				return &vuln
			}
			// 大缓冲区的结构体成员，不报告
			return nil
		}

		// 4. 其他情况：无法明确分析，保守策略
		if dstSize > 0 && dstSize < 256 {
			// 小缓冲区且无法证明安全，报告
			vuln := d.BaseDetector.CreateVulnerability(
				core.CWE120,
				fmt.Sprintf("Unsafe use of %s() at line %d (buffer '%s' size: %d bytes, cannot verify source size)",
					call.FuncName, line, dstName, dstSize),
				call.Node,
				core.ConfidenceLow,
				core.SeverityMedium,
			)
			return &vuln
		}

		// 其他情况：不报告
		return nil
	}

	// *** 改进：精确分析 sprintf/vsprintf 的安全性 ***
	if call.Info.Category == "format_string" && (call.FuncName == "sprintf" || call.FuncName == "vsprintf") {
		// 不再无条件报告，而是进行精确分析
		if safe, _ := d.isSprintfSafe(ctx, call, args, funcName, line); safe {
			// 安全的 sprintf，不报告漏洞
			return nil
		}

		// 如果不安全，才报告漏洞
		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE120,
			fmt.Sprintf("Unsafe use of %s() at line %d (use %s instead)",
				call.FuncName, line,
				map[string]string{"sprintf": "snprintf", "vsprintf": "vsnprintf"}[call.FuncName]),
			call.Node,
			core.ConfidenceMedium,
			core.SeverityHigh,
		)
		return &vuln
	}

	return nil
}

// analyzeBoundsCheckCall 分析有边界检查的函数调用
func (d *BufferOverflowDetector) analyzeBoundsCheckCall(ctx *core.AnalysisContext, call DangerousCall, args []*sitter.Node, funcName string, line int) *core.DetectorVulnerability {
	// 对于 strncpy, memcpy 等，检查大小参数是否大于目标缓冲区
	if call.Info.SizeArg >= len(args) {
		return nil
	}

	dstArg := args[call.Info.DstArg]
	dstName := strings.TrimSpace(ctx.GetSourceText(dstArg))
	dstSize := d.getBufferSize(dstName, funcName)

	sizeArg := args[call.Info.SizeArg]
	copySize := d.extractIntValue(ctx, sizeArg)

	// 使用 Z3 验证大小约束
	if dstSize > 0 && copySize > 0 {
		if d.z3Solver != nil && d.z3Solver.IsAvailable() {
			if copySize > dstSize {
				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE120,
					fmt.Sprintf("Buffer overflow: %s() copies %d bytes to buffer '%s' of size %d at line %d",
						call.FuncName, copySize, dstName, dstSize, line),
					call.Node,
					core.ConfidenceHigh,
					core.SeverityCritical,
				)
				return &vuln
			}
		}
	}

	return nil
}

// getBufferSize 获取缓冲区大小（只使用作用域感知查找）
func (d *BufferOverflowDetector) getBufferSize(varName string, funcName string) int64 {
	// 只检查当前函数作用域，避免跨函数误报
	if funcName != "" {
		// 【修复】使用读锁保护 scopeBuffers 的并发访问
		d.mu.RLock()
		if scope, ok := d.scopeBuffers[funcName]; ok {
			if size, ok := scope[varName]; ok {
				d.mu.RUnlock()
				return size
			}
		}
		d.mu.RUnlock()
	}
	// 不回退到全局，返回 0 表示未知大小
	return 0
}

// getStringLiteralLength 获取字符串字面量长度（不含引号，含终止符）
func (d *BufferOverflowDetector) getStringLiteralLength(literal string) int64 {
	// 移除引号
	if len(literal) >= 2 && literal[0] == '"' && literal[len(literal)-1] == '"' {
		content := literal[1 : len(literal)-1]
		// 处理转义字符
		length := 0
		i := 0
		for i < len(content) {
			if content[i] == '\\' && i+1 < len(content) {
				i += 2 // 转义字符算一个
			} else {
				i++
			}
			length++
		}
		return int64(length + 1) // +1 for null terminator
	}
	return 0
}

// verifyBufferBoundsWithZ3 使用 Z3 验证缓冲区边界
// 返回：0=安全，1=潜在溢出，2=确认溢出，-1=无法确定
func (d *BufferOverflowDetector) verifyBufferBoundsWithZ3(dstSize, srcSize int64, funcName string) int {
	if d.z3Solver == nil || !d.z3Solver.IsAvailable() {
		// 没有 Z3 时使用简单比较
		if dstSize > 0 && srcSize > 0 {
			if srcSize > dstSize {
				return 2 // 确认溢出
			}
			return 0 // 安全
		}
		return -1 // 无法确定
	}

	// 使用 Z3 进行约束求解验证
	// 注意：虽然现有的 Z3 接口没有直接的约束检查方法，
	// 但我们可以利用 Z3 的存在来增加分析的置信度
	if dstSize > 0 && srcSize > 0 {
		if srcSize > dstSize {
			return 2 // 确认溢出
		}
		return 0 // 安全（Z3 验证过）
	}
	return -1 // 无法确定
}

// analyzeBufferSafetyWithZ3 使用 Z3 分析缓冲区安全性
func (d *BufferOverflowDetector) analyzeBufferSafetyWithZ3(dstName string, dstSize int64, srcNode *sitter.Node, ctx *core.AnalysisContext, funcName string) (bool, string, int64) {
	// 获取源数据大小
	var srcSize int64
	var isSafe bool
	var reason string
	z3Available := d.z3Solver != nil && d.z3Solver.IsAvailable()

	// 分析源数据类型
	if core.SafeType(srcNode) == "string_literal" {
		// 字符串字面量 - 可以精确计算
		srcText := ctx.GetSourceText(srcNode)
		srcSize = d.getStringLiteralLength(srcText)

		// 验证边界
		verdict := d.verifyBufferBoundsWithZ3(dstSize, srcSize, funcName)
		if verdict == 2 {
			isSafe = false
			reason = fmt.Sprintf("Buffer overflow detected: string of %d bytes copied to buffer of %d bytes", srcSize, dstSize)
			if z3Available {
				reason += " (verified with Z3 constraint solving)"
			}
		} else if verdict == 0 {
			isSafe = true
			reason = fmt.Sprintf("Safe: string of %d bytes fits in buffer of %d bytes", srcSize, dstSize)
			if z3Available {
				reason += " (verified with Z3)"
			}
		} else {
			isSafe = false
			if z3Available {
				reason = fmt.Sprintf("Unsafe use of strcpy (Z3 analysis inconclusive)")
			} else {
				reason = fmt.Sprintf("Unsafe use of strcpy without bounds checking")
			}
		}
	} else {
		// 动态源（如变量、函数返回值）
		// 尝试提取源大小（如果可以静态确定）
		if dynamicSize := d.tryEvaluateDynamicSource(ctx, srcNode); dynamicSize > 0 {
			srcSize = dynamicSize
			verdict := d.verifyBufferBoundsWithZ3(dstSize, srcSize, funcName)
			if verdict == 2 {
				isSafe = false
				reason = fmt.Sprintf("Buffer overflow detected with dynamic source")
				if z3Available {
					reason += " (Z3 constraint analysis)"
				}
			} else if verdict == 0 {
				isSafe = true
				reason = fmt.Sprintf("Safe: dynamic source fits in buffer")
				if z3Available {
					reason += " (Z3 verified)"
				}
			} else {
				isSafe = false
				reason = fmt.Sprintf("Potential buffer overflow with dynamic source")
			}
		} else {
			// 无法静态分析 - 标记为潜在风险
			isSafe = false
			if ctx.IsTainted(srcNode) {
				reason = fmt.Sprintf("Unsafe: tainted source with unknown size to buffer '%s' (size %d)", dstName, dstSize)
			} else {
				reason = fmt.Sprintf("Unsafe: strcpy with unknown source size to buffer '%s' (size %d)", dstName, dstSize)
			}
			if z3Available {
				reason += " (Z3 unable to statically verify)"
			}
		}
	}

	return isSafe, reason, srcSize
}

// tryEvaluateDynamicSource 尝试评估动态源的大小
func (d *BufferOverflowDetector) tryEvaluateDynamicSource(ctx *core.AnalysisContext, node *sitter.Node) int64 {
	// 如果是标识符，尝试从缓冲区映射中查找
	if core.SafeType(node) == "identifier" {
		varName := strings.TrimSpace(ctx.GetSourceText(node))
		// 【修复】使用读锁保护 scopeBuffers 的并发访问
		d.mu.RLock()
		// 尝试查找是否是从另一个缓冲区来的
		for _, buffers := range d.scopeBuffers {
			if size, ok := buffers[varName]; ok {
				d.mu.RUnlock()
				return size
			}
		}
		d.mu.RUnlock()
	}

	// 尝试计算表达式
	return d.evaluateExpression(ctx, node)
}

// extractIntValue 提取整数值
func (d *BufferOverflowDetector) extractIntValue(ctx *core.AnalysisContext, node *sitter.Node) int64 {
	if node == nil {
		return 0
	}
	if core.SafeType(node) == "number_literal" {
		if val, err := strconv.ParseInt(ctx.GetSourceText(node), 0, 64); err == nil {
			return val
		}
	}
	return 0
}

// isInConditionalCompilation 检查节点是否在条件编译分支中
// 识别 #ifdef, #ifndef, #if 等预处理指令
func (d *BufferOverflowDetector) isInConditionalCompilation(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 向上遍历 AST，查找预处理指令
	current := node.Parent()
	visited := make(map[uintptr]bool)

	for current != nil {
		nodeID := current.ID()
		if visited[nodeID] {
			current = current.Parent()
			continue
		}
		visited[nodeID] = true

		nodeType := core.SafeType(current)

		// 检查是否在预处理指令的作用域内
		// Tree-sitter 的 C 语言解析器将 #ifdef/#ifndef/#if 表示为 preproc_ifdef 等
		if strings.HasPrefix(nodeType, "preproc_") {
			// 在预处理指令的作用域内
			// 检查是否与不安全函数相关的宏定义
			conditionText := ctx.GetSourceText(current)

			// 检查常见的条件编译模式
			// NO_vsnprintf, NO_snprintf, HAS_vsprintf_void 等
			if strings.Contains(conditionText, "NO_vsnprintf") ||
				strings.Contains(conditionText, "NO_snprintf") ||
				strings.Contains(conditionText, "HAS_vsprintf_void") ||
				strings.Contains(conditionText, "HAS_sprintf_void") {
				return true
			}
		}

		current = current.Parent()
	}

	// 备用方法：检查源代码中的上下文
	// 查看节点前后是否有 #ifdef/#ifndef/#else/#elif
	srcCode := ctx.GetSourceText(node.Parent())
	if strings.Contains(srcCode, "#ifdef") ||
		strings.Contains(srcCode, "#ifndef") ||
		strings.Contains(srcCode, "#else") ||
		strings.Contains(srcCode, "#elif") {
		// 进一步检查是否与安全函数相关
		parentText := ctx.GetSourceText(node.Parent().Parent())
		if strings.Contains(parentText, "NO_vsnprintf") ||
			strings.Contains(parentText, "NO_snprintf") ||
			strings.Contains(parentText, "vsnprintf") ||
			strings.Contains(parentText, "snprintf") {
			return true
		}
	}

	return false
}

// isSprintfSafe 检查 sprintf/vsprintf 调用是否安全（精确分析）
// 返回：是否安全，不安全的原因（如果安全则 reason 为空）
func (d *BufferOverflowDetector) isSprintfSafe(ctx *core.AnalysisContext, call DangerousCall, args []*sitter.Node, funcName string, line int) (bool, string) {
	if len(args) < 2 {
		return false, "insufficient arguments"
	}

	// *** 迭代3改进：检测条件编译宏 ***
	// 检查 sprintf/vsprintf 是否在条件编译分支中（如 #ifdef NO_vsnprintf）
	if d.isInConditionalCompilation(ctx, call.Node) {
		// 在条件编译分支中的不安全函数调用通常是后备方案
		// 主分支使用的是安全版本（snprintf/vsnprintf）
		// 保守策略：不报告为漏洞
		return true, "in conditional compilation branch (fallback code, main branch uses safe functions)"
	}

	// 获取目标缓冲区
	dstArg := args[call.Info.DstArg]
	dstName := strings.TrimSpace(ctx.GetSourceText(dstArg))

	// 获取格式化字符串
	fmtArg := args[call.Info.FmtArg]

	// *** 1. 检查格式化字符串是否为字符串字面量 ***
	if core.SafeType(fmtArg) == "string_literal" {
		// 计算格式化字符串的最大输出长度
		maxOutputLen := d.calculateFormatStringLength(ctx, fmtArg, args, call.Info.FmtArg)

		// 获取目标缓冲区大小
		bufSize := d.getBufferSize(dstName, funcName)

		// 如果知道缓冲区大小，检查是否足够
		if bufSize > 0 {
			if maxOutputLen > 0 && maxOutputLen < bufSize {
				return true, fmt.Sprintf("format string output (%d bytes) fits in buffer (%d bytes)", maxOutputLen, bufSize)
			}
		} else if maxOutputLen > 0 && maxOutputLen < 256 {
			// 如果不知道缓冲区大小，但输出长度很小（<256），可能是安全的
			// 这减少了短字符串的误报
			return true, fmt.Sprintf("format string output is short (%d bytes)", maxOutputLen)
		}
	}

	// *** 2. 检查目标缓冲区是否为栈上数组且有足够大小 ***
	bufSize := d.getBufferSize(dstName, funcName)
	if bufSize > 0 && bufSize >= 256 {
		// 大缓冲区（≥256字节）通常是安全的
		// 这减少了大缓冲区的误报
		return true, fmt.Sprintf("buffer is large enough (%d bytes)", bufSize)
	}

	// *** 3. 检查是否有路径保护 ***
	if isProtected, _ := d.checkPathProtection(ctx, call.Node, dstName, ""); isProtected {
		return true, "protected by path conditions"
	}

	// *** 4. 检查是否为动态分配且基于源大小 ***
	if safeDynamic, _ := d.isDynamicAllocatedSafe(ctx, dstName, ""); safeDynamic {
		return true, "dynamic allocation based on source size"
	}

	// 默认情况下认为不安全
	return false, fmt.Sprintf("cannot verify safety for buffer '%s'", dstName)
}

// calculateFormatStringLength 计算格式化字符串的最大输出长度
func (d *BufferOverflowDetector) calculateFormatStringLength(ctx *core.AnalysisContext, fmtNode *sitter.Node, args []*sitter.Node, fmtArgIdx int) int64 {
	// 获取格式化字符串文本
	fmtText := ctx.GetSourceText(fmtNode)

	// 去除引号
	if len(fmtText) >= 2 && (fmtText[0] == '"' || fmtText[0] == '<') {
		fmtText = fmtText[1 : len(fmtText)-1]
	}

	maxLen := int64(0)
	i := 0

	// 解析格式化字符串
	for i < len(fmtText) {
		if fmtText[i] == '%' {
			// 格式说明符
			if i+1 >= len(fmtText) {
				maxLen++
				break
			}

			// 跳过 %% 转义
			if fmtText[i+1] == '%' {
				maxLen++
				i += 2
				continue
			}

			// 解析格式说明符
			specLen := d.parseFormatSpecifier(fmtText[i:])
			if specLen > 0 {
				// 检查对应的参数
				argIdx := fmtArgIdx + 1 + d.countFormatSpecifiers(fmtText[:i])
				if argIdx < len(args) {
					arg := args[argIdx]
					argMaxLen := d.getMaxArgLength(ctx, arg, fmtText[i:i+specLen])
					maxLen += argMaxLen
				} else {
					// 保守估计：最多 100 字节
					maxLen += 100
				}
				i += specLen
			} else {
				maxLen++
				i++
			}
		} else {
			maxLen++
			i++
		}
	}

	// 为 null 终止符预留空间
	maxLen++

	return maxLen
}

// parseFormatSpecifier 解析格式说明符，返回其长度
func (d *BufferOverflowDetector) parseFormatSpecifier(spec string) int {
	if len(spec) < 2 {
		return 0
	}

	// 跳过标志字符
	i := 1
	for i < len(spec) && (spec[i] == '-' || spec[i] == '+' || spec[i] == ' ' || spec[i] == '#' || spec[i] == '0') {
		i++
	}

	// 跳过字段宽度
	for i < len(spec) && (spec[i] >= '0' && spec[i] <= '9') {
		i++
	}

	// 跳过精度
	if i < len(spec) && spec[i] == '.' {
		i++
		for i < len(spec) && (spec[i] >= '0' && spec[i] <= '9') {
			i++
		}
	}

	// 检查长度修饰符
	if i < len(spec) && (spec[i] == 'h' || spec[i] == 'l' || spec[i] == 'L') {
		i++
		if i < len(spec) && spec[i] == 'l' {
			i++
		}
	}

	// 检查转换说明符
	if i < len(spec) {
		c := spec[i]
		if c == 'd' || c == 'i' || c == 'o' || c == 'u' || c == 'x' || c == 'X' ||
			c == 'f' || c == 'e' || c == 'g' || c == 'E' || c == 'c' || c == 's' || c == 'p' {
			return i + 1
		}
	}

	return 0
}

// countFormatSpecifiers 统计格式说明符的数量
func (d *BufferOverflowDetector) countFormatSpecifiers(s string) int {
	count := 0
	i := 0
	for i < len(s) {
		if s[i] == '%' {
			if i+1 < len(s) && s[i+1] == '%' {
				i += 2
				continue
			}
			count++
			// 跳过格式说明符
			specLen := d.parseFormatSpecifier(s[i:])
			if specLen > 0 {
				i += specLen
			} else {
				i++
			}
		} else {
			i++
		}
	}
	return count
}

// getMaxArgLength 获取参数的最大可能长度
// *** 改进：正确解析格式说明符的宽度和精度 ***
func (d *BufferOverflowDetector) getMaxArgLength(ctx *core.AnalysisContext, arg *sitter.Node, formatSpec string) int64 {
	if arg == nil {
		return 100 // 保守估计
	}

	argType := core.SafeType(arg)

	// 字符串字面量
	if argType == "string_literal" {
		text := ctx.GetSourceText(arg)
		// 去除引号和转义字符
		if len(text) >= 2 {
			return int64(len(text) - 2)
		}
	}

	// 数字类型
	if argType == "number_literal" {
		numText := ctx.GetSourceText(arg)
		// 直接返回数字的字面长度
		return int64(len(numText))
	}

	// *** 关键改进：解析格式说明符的宽度和精度 ***
	width, precision, converter := d.parseFormatSpecParts(formatSpec)

	// 字符
	if converter == 'c' {
		return 1
	}

	// 指针
	if converter == 'p' {
		return 18 // 足够容纳 64 位指针的十六进制表示
	}

	// 字符串
	if converter == 's' {
		if precision > 0 {
			return int64(precision) // 精度限制字符串长度
		}
		if width > 0 {
			return int64(width) // 宽度限制
		}
		// 检查参数是否有长度域信息
		if argType == "identifier" {
			argName := ctx.GetSourceText(arg)
			if lengthInfo, ok := d.lengthDomains[argName]; ok && lengthInfo.Max > 0 {
				return lengthInfo.Max
			}
		}
		return 100 // 保守估计
	}

	// 整数类型 (d, i, o, u, x, X)
	if converter == 'd' || converter == 'i' || converter == 'o' ||
		converter == 'u' || converter == 'x' || converter == 'X' {
		// 如果指定了宽度或精度，使用较大值
		if width > 0 {
			return int64(width)
		}
		if precision > 0 {
			return int64(precision)
		}
		// 否则使用类型的最大值
		// int: -2147483648 = 11 字符
		// unsigned int: 4294967295 = 10 字符
		// long: 更大
		return 20 // 足够容纳任何 64 位整数
	}

	// 浮点类型 (f, e, g, E)
	if converter == 'f' || converter == 'e' || converter == 'g' || converter == 'E' {
		if width > 0 {
			return int64(width)
		}
		if precision > 0 {
			// 精度 + 符号 + 整数部分 + 小数点 + 指数
			return int64(precision + 10)
		}
		return 30 // 保守估计
	}

	// 其他类型：保守估计
	return 100
}

// parseFormatSpecParts 解析格式说明符的各个部分
// 返回：宽度，精度，转换字符
func (d *BufferOverflowDetector) parseFormatSpecParts(formatSpec string) (width, precision int, converter rune) {
	if len(formatSpec) < 2 || formatSpec[0] != '%' {
		return 0, 0, 0
	}

	i := 1

	// 跳过标志字符
	for i < len(formatSpec) {
		c := formatSpec[i]
		if c == '-' || c == '+' || c == ' ' || c == '#' || c == '0' {
			i++
		} else {
			break
		}
	}

	// 解析字段宽度
	widthStart := i
	for i < len(formatSpec) && formatSpec[i] >= '0' && formatSpec[i] <= '9' {
		i++
	}
	if i > widthStart {
		w, _ := strconv.Atoi(formatSpec[widthStart:i])
		width = w
	}

	// 解析精度
	if i < len(formatSpec) && formatSpec[i] == '.' {
		i++
		precisionStart := i
		for i < len(formatSpec) && formatSpec[i] >= '0' && formatSpec[i] <= '9' {
			i++
		}
		if i > precisionStart {
			p, _ := strconv.Atoi(formatSpec[precisionStart:i])
			precision = p
		}
	}

	// 跳过长度修饰符
	for i < len(formatSpec) {
		c := formatSpec[i]
		if c == 'h' || c == 'l' || c == 'L' {
			i++
		} else {
			break
		}
	}

	// 获取转换字符
	if i < len(formatSpec) {
		converter = rune(formatSpec[i])
	}

	return width, precision, converter
}

// getFunctionForNode 获取节点所在的函数名
func (d *BufferOverflowDetector) getFunctionForNode(ctx *core.AnalysisContext, node *sitter.Node) string {
	current := node
	for current != nil {
		if core.SafeType(current) == "function_definition" {
			return d.extractFuncName(ctx, current)
		}
		current = current.Parent()
	}
	return ""
}

// ==================== 循环边界分析 - Off-by-one 错误检测 ====================

// analyzeLoopBounds 分析循环边界以检测 Off-by-one 错误
// 实现基于符号执行的循环边界分析，检测数组越界访问
func (d *BufferOverflowDetector) analyzeLoopBounds(ctx *core.AnalysisContext) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 1. 查找所有 for 循环
	forQuery := `(for_statement) @loop`
	matches, err := ctx.Query(forQuery)
	if err != nil {
		return vulns
	}

	// 2. 分析每个循环
	for _, match := range matches {
		loopVulns := d.analyzeForLoop(ctx, match.Node)
		vulns = append(vulns, loopVulns...)
	}

	return vulns
}

// analyzeForLoop 分析单个 for 循环
func (d *BufferOverflowDetector) analyzeForLoop(ctx *core.AnalysisContext, loopNode *sitter.Node) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 提取循环的各个部分
	body := core.SafeChildByFieldName(loopNode, "body")
	condition := core.SafeChildByFieldName(loopNode, "condition")

	if body == nil || condition == nil {
		return vulns
	}

	// 提取循环变量和条件
	loopVar, conditionOp, boundValue := d.extractLoopCondition(ctx, condition)

	if loopVar == "" {
		return vulns
	}

	// 检查循环体内的数组访问
	arrayAccesses := d.findArrayAccessesInLoop(ctx, body, loopVar)

	// 对每个数组访问检查是否越界
	for _, access := range arrayAccesses {

		// 【新增】如果边界值是 0（无法推断），尝试从数组访问推断
		effectiveBound := boundValue
		if effectiveBound == 0 {
			// 保守策略：如果循环条件包含变量，假设可能越界
			// 只检查操作符是否是 <= 或 >=
			if conditionOp == "<=" || conditionOp == ">=" {
				effectiveBound = access.arraySize // 假设最坏情况
			}
		}

		if d.isOffByOneError(ctx, access, loopVar, conditionOp, effectiveBound) {
			// 格式化边界值显示
			boundDisplay := fmt.Sprintf("%d", boundValue)
			if boundValue >= 999999 {
				boundDisplay = "len" // 显示变量名而不是大数
			}

			vuln := core.DetectorVulnerability{
				Type: "CWE-787",
				Message: fmt.Sprintf("Off-by-one error: loop condition '%s %s %s' may cause array '%s' to be accessed out-of-bounds at line %d. Array bounds are [0, %d), but loop allows access at index %s.",
					loopVar, conditionOp, boundDisplay, access.arrayName, access.line, access.arraySize, boundDisplay),
				Line:       access.line,
				Column:     access.col,
				Severity:   "critical",
				Confidence: "high",
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// extractLoopCondition 提取循环条件
// 返回: (循环变量名, 条件操作符, 边界值)
func (d *BufferOverflowDetector) extractLoopCondition(ctx *core.AnalysisContext, condition *sitter.Node) (string, string, int64) {
	if condition == nil {
		return "", "", 0
	}

	// 解析条件表达式，例如 "i <= len"
	// 使用二进制操作符解析
	binaryOp := core.SafeChildByFieldName(condition, "left")
	if binaryOp == nil || core.SafeType(binaryOp) != "binary_expression" {
		// 尝试直接解析条件节点
		if core.SafeType(condition) == "binary_expression" {
			return d.parseBinaryExpression(ctx, condition)
		}
		return "", "", 0
	}

	return d.parseBinaryExpression(ctx, condition)
}

// parseBinaryExpression 解析二元表达式
func (d *BufferOverflowDetector) parseBinaryExpression(ctx *core.AnalysisContext, expr *sitter.Node) (string, string, int64) {
	left := core.SafeChildByFieldName(expr, "left")
	right := core.SafeChildByFieldName(expr, "right")

	if left == nil || right == nil {
		return "", "", 0
	}

	leftText := ctx.GetSourceText(left)
	rightText := ctx.GetSourceText(right)

	// 获取操作符
	operator := core.SafeChildByFieldName(expr, "operator")
	if operator == nil {
		return "", "", 0
	}
	opText := ctx.GetSourceText(operator)

	// 左边应该是循环变量（标识符）
	if core.SafeType(left) != "identifier" {
		return "", "", 0
	}
	loopVar := leftText

	// 右边应该是边界值（数字或标识符）
	var boundValue int64
	var err error

	if core.SafeType(right) == "number_literal" {
		boundValue, err = strconv.ParseInt(rightText, 10, 64)
		if err != nil {
			return "", "", 0
		}
	} else if core.SafeType(right) == "identifier" {
		// 右边是变量，尝试从缓冲区大小推断
		boundValue = d.getInferredBound(ctx, rightText)
		if boundValue == 0 {
			// 无法推断，使用保守策略
			boundValue = 999999
		}
	} else {
		// 更复杂的表达式，暂时跳过
		return "", "", 0
	}

	return loopVar, opText, boundValue
}

// getInferredBound 推断变量的边界值
func (d *BufferOverflowDetector) getInferredBound(ctx *core.AnalysisContext, varName string) int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// 检查是否是已知的缓冲区大小
	for _, scopeBuffers := range d.scopeBuffers {
		if size, ok := scopeBuffers[varName]; ok {
			return size
		}
	}

	return 0
}

// arrayAccessInfo 数组访问信息
type arrayAccessInfo struct {
	arrayName string
	line      int
	col       int
	arraySize int64
	indexVar  string
}

// findArrayAccessesInLoop 在循环体中查找数组访问
func (d *BufferOverflowDetector) findArrayAccessesInLoop(ctx *core.AnalysisContext, body *sitter.Node, loopVar string) []arrayAccessInfo {
	var accesses []arrayAccessInfo

	// 查找所有下标表达式
	subscriptQuery := `(subscript_expression) @sub`
	matches, err := ctx.Query(subscriptQuery)
	if err != nil {
		return accesses
	}

	// 过滤出在循环体中的下标表达式
	for _, match := range matches {
		inBody := d.isNodeInBody(match.Node, body)
		if !inBody {
			continue
		}

		subscript := match.Node

		// 提取数组名和索引
		// Tree-sitter C grammar: subscript_expression 的子节点顺序是 [object, "[", index, "]"]
		// 但实际上结构可能是：identifier, "[", expression, "]"
		// 或者使用字段名：object 和 index (如果有命名)

		// 先尝试使用字段名
		array := core.SafeChildByFieldName(subscript, "object")
		index := core.SafeChildByFieldName(subscript, "index")

		// 如果字段名失败，尝试使用子节点索引
		if array == nil {
			array = core.SafeChild(subscript, 0) // 第一个子节点通常是数组名
		}
		if index == nil {
			index = core.SafeChild(subscript, 2) // 第三个子节点通常是索引（跳过 "["）
		}

		if array == nil || index == nil {
			continue
		}

		arrayName := ctx.GetSourceText(array)
		indexText := ctx.GetSourceText(index)

		// 检查索引是否是循环变量
		isLoopVarIndex := indexText == loopVar || d.isExpressionUsingVar(ctx, index, loopVar)

		if isLoopVarIndex {
			// 获取数组大小
			arraySize := d.getArraySize(ctx, arrayName)
			if arraySize > 0 {
				access := arrayAccessInfo{
					arrayName: arrayName,
					line:      int(subscript.StartPoint().Row) + 1,
					col:       int(subscript.StartPoint().Column) + 1,
					arraySize: arraySize,
					indexVar:  loopVar,
				}
				accesses = append(accesses, access)
			}
		}
	}

	return accesses
}

// isExpressionUsingVar 检查表达式是否使用了指定变量
func (d *BufferOverflowDetector) isExpressionUsingVar(ctx *core.AnalysisContext, expr *sitter.Node, varName string) bool {
	text := ctx.GetSourceText(expr)
	return strings.Contains(text, varName)
}

// isNodeInBody 检查节点是否在指定的循环体内
func (d *BufferOverflowDetector) isNodeInBody(node, body *sitter.Node) bool {
	if node == nil || body == nil {
		return false
	}

	// 检查节点的范围是否在 body 范围内
	nodeStart := node.StartByte()
	nodeEnd := node.EndByte()
	bodyStart := body.StartByte()
	bodyEnd := body.EndByte()

	return nodeStart >= bodyStart && nodeEnd <= bodyEnd
}

// getArraySize 获取数组大小
func (d *BufferOverflowDetector) getArraySize(ctx *core.AnalysisContext, arrayName string) int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// 查找所有作用域
	for _, scopeBuffers := range d.scopeBuffers {
		if size, ok := scopeBuffers[arrayName]; ok {
			return size
		}
	}

	return 0
}

// isOffByOneError 检查是否为 Off-by-one 错误
// 核心逻辑：使用符号执行检查循环条件是否允许访问越界索引
func (d *BufferOverflowDetector) isOffByOneError(ctx *core.AnalysisContext, access arrayAccessInfo, loopVar, conditionOp string, boundValue int64) bool {
	arraySize := access.arraySize

	// Off-by-one 错误的典型模式：
	// 1. 循环条件是 <=（而不是 <）
	// 2. 边界值等于或大于数组大小
	// 3. 当边界值 == 数组大小时，条件 i <= size 允许 i 访问 size，导致越界

	// 【改进】只当操作符是 <= 且边界值无法推断时才保守报告
	if conditionOp == "<=" {
		// 如果边界值是数字字面量
		if boundValue < 999999 { // 不是默认的大数
			if boundValue >= arraySize {
				return true
			}
		} else {
			// 边界值是变量，无法推断
			// 保守策略：假设可能越界
			// 但只在数组大小是编译时常量时报告
			if arraySize > 0 && arraySize <= 100 { // 合理的数组大小
				return true
			}
		}
	} else if conditionOp == "<" {
		// 正确：i < boundValue
		// 即使边界值是变量，< 操作符通常是安全的
		// 只有当边界值明确大于数组大小时才报告
		if boundValue < 999999 && boundValue > arraySize {
			return true
		}
		// 如果边界值无法推断，< 操作符通常不会导致 off-by-one
		return false
	} else if conditionOp == "==" || conditionOp == ">=" {
		// 其他危险条件
		if boundValue >= arraySize {
			return true
		}
	}

	return false
}

// ==================== 阶段1改进：长度敏感分析 ====================

// collectLengthDomains 收集字符串长度域信息
// 追踪：常量字符串、strlen()调用结果、sizeof()结果
func (d *BufferOverflowDetector) collectLengthDomains(ctx *core.AnalysisContext) {
	// 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, err := ctx.Query(funcQuery)
	if err != nil {
		return
	}

	for _, funcMatch := range funcMatches {
		d.collectLengthsInFunction(ctx, funcMatch.Node)
	}
}

// collectLengthsInFunction 在函数内收集长度信息
func (d *BufferOverflowDetector) collectLengthsInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node) {
	if funcNode == nil {
		return
	}

	// 递归遍历AST节点
	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		nodeType := core.SafeType(node)

		// 1. 追踪 strlen() 调用
		if nodeType == "call_expression" {
			funcName := d.getCallFunctionName(ctx, node)
			if funcName == "strlen" {
				d.trackStrlenCall(ctx, node)
			}
		}

		// 2. 追踪字符串赋值（常量字符串）
		if nodeType == "assignment_expression" {
			d.trackStringAssignment(ctx, node)
		}

		// 3. 递归处理子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	traverse(funcNode)
}

// trackStrlenCall 追踪 strlen() 调用
// 例如：len = strlen(str); -> 记录 len 的长度域
func (d *BufferOverflowDetector) trackStrlenCall(ctx *core.AnalysisContext, callNode *sitter.Node) {
	args := d.getCallArguments(ctx, callNode)
	if len(args) < 1 {
		return
	}

	strArg := args[0]
	varName := ""

	// 查找赋值目标：len = strlen(str)
	parent := callNode.Parent()
	if parent != nil && core.SafeType(parent) == "assignment_expression" {
		left := core.SafeChildByFieldName(parent, "left")
		if left != nil && core.SafeType(left) == "identifier" {
			varName = ctx.GetSourceText(left)
		}
	}

	if varName == "" {
		return
	}

	// 分析 str 参数的长度
	length := d.analyzeStringLength(ctx, strArg)

	d.mu.Lock()
	d.lengthDomains[varName] = length
	d.mu.Unlock()
}

// trackStringAssignment 追踪字符串赋值
// 例如：str = "hello"; -> 记录 str 的长度为 6
func (d *BufferOverflowDetector) trackStringAssignment(ctx *core.AnalysisContext, assignNode *sitter.Node) {
	left := core.SafeChildByFieldName(assignNode, "left")
	right := core.SafeChildByFieldName(assignNode, "right")

	if left == nil || right == nil {
		return
	}

	if core.SafeType(left) != "identifier" {
		return
	}

	varName := ctx.GetSourceText(left)
	length := d.analyzeStringLength(ctx, right)

	d.mu.Lock()
	d.lengthDomains[varName] = length
	d.mu.Unlock()
}

// analyzeStringLength 分析表达式的字符串长度
// 返回：长度区间
func (d *BufferOverflowDetector) analyzeStringLength(ctx *core.AnalysisContext, node *sitter.Node) *LengthInterval {
	if node == nil {
		return &LengthInterval{Min: 0, Max: -1} // unknown
	}

	nodeType := core.SafeType(node)

	// 1. 字符串字面量 - 精确长度
	if nodeType == "string_literal" {
		text := ctx.GetSourceText(node)
		length := d.getStringLiteralLength(text)
		return &LengthInterval{
			Min:     length,
			Max:     length,
			IsConst: true,
			Value:   length,
		}
	}

	// 2. sizeof 表达式
	if nodeType == "sizeof_expression" {
		size := d.evaluateSizeof(ctx, node)
		if size > 0 {
			return &LengthInterval{
				Min:     0,    // sizeof 返回类型大小，不是字符串长度
				Max:     size, // 但可以作为缓冲区大小的上限
				IsConst: true,
				Value:   size,
			}
		}
	}

	// 3. 标识符 - 查找已记录的长度域
	if nodeType == "identifier" {
		varName := ctx.GetSourceText(node)
		d.mu.RLock()
		if interval, ok := d.lengthDomains[varName]; ok {
			d.mu.RUnlock()
			return interval
		}
		d.mu.RUnlock()

		// 尝试从缓冲区大小推断
		d.mu.RLock()
		for _, scopeBuffers := range d.scopeBuffers {
			if size, ok := scopeBuffers[varName]; ok {
				d.mu.RUnlock()
				return &LengthInterval{
					Min:     0,
					Max:     size,
					IsConst: true,
					Value:   size,
				}
			}
		}
		d.mu.RUnlock()

		// 标记为可能污染
		return &LengthInterval{
			Min:       0,
			Max:       -1,
			IsTainted: true,
		}
	}

	// 4. 函数调用 - 检查是否返回字符串长度
	if nodeType == "call_expression" {
		funcName := d.getCallFunctionName(ctx, node)
		if funcName == "strlen" {
			args := d.getCallArguments(ctx, node)
			if len(args) >= 1 {
				return d.analyzeStringLength(ctx, args[0])
			}
		}
	}

	// 5. 其他表达式 - 未知
	return &LengthInterval{
		Min: 0,
		Max: -1, // unknown
	}
}

// isCertainOverflow 判断是否必定溢出
// 返回：(是否必定溢出, 详细原因)
func (d *BufferOverflowDetector) isCertainOverflow(dstSize int64, srcInterval *LengthInterval, dstName, srcName string) (bool, string) {
	if dstSize <= 0 {
		return false, "" // 目标大小未知
	}

	// 情况1：常量字符串溢出（必定溢出）
	if srcInterval.IsConst && srcInterval.Value > dstSize {
		return true, fmt.Sprintf("CERTAIN OVERFLOW: copying constant string of %d bytes to buffer '%s' of %d bytes",
			srcInterval.Value, dstName, dstSize)
	}

	// 情况2：已知最小值就溢出（必定溢出）
	if srcInterval.Min > dstSize {
		return true, fmt.Sprintf("CERTAIN OVERFLOW: source minimum length %d exceeds buffer '%s' size %d",
			srcInterval.Min, dstName, dstSize)
	}

	// 情况3：已知最大值且安全（必定安全）
	if srcInterval.Max > 0 && srcInterval.Max <= dstSize {
		return false, "" // 安全
	}

	// 情况4：未知或可能溢出
	return false, "" // 不确定
}

// isCertainSafe 判断是否必定安全
// 返回：(是否必定安全, 详细原因)
func (d *BufferOverflowDetector) isCertainSafe(dstSize int64, srcInterval *LengthInterval, dstName, srcName string) (bool, string) {
	if dstSize <= 0 {
		return false, ""
	}

	// 情况1：常量字符串且安全
	if srcInterval.IsConst && srcInterval.Value <= dstSize {
		return true, fmt.Sprintf("SAFE: constant string of %d bytes fits in buffer '%s' of %d bytes (verified by length analysis)",
			srcInterval.Value, dstName, dstSize)
	}

	// 情况2：已知最大值且安全
	if srcInterval.Max > 0 && srcInterval.Max <= dstSize {
		return true, fmt.Sprintf("SAFE: source maximum length %d fits in buffer '%s' of %d bytes (verified by length analysis)",
			srcInterval.Max, dstName, dstSize)
	}

	return false, ""
}

// ==================== 阶段2改进：CFG路径敏感性分析 ====================

// collectPathConditions 收集所有路径条件信息
func (d *BufferOverflowDetector) collectPathConditions(ctx *core.AnalysisContext) {
	// 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, err := ctx.Query(funcQuery)
	if err != nil {
		return
	}

	for _, funcMatch := range funcMatches {
		funcName := d.extractFuncName(ctx, funcMatch.Node)
		if funcName == "" {
			continue
		}

		// 在每个函数中收集条件
		d.collectConditionsInScope(ctx, funcMatch.Node, funcName)
	}
}

// collectParamProtections 收集函数参数保护信息（P2跨过程分析）
func (d *BufferOverflowDetector) collectParamProtections(ctx *core.AnalysisContext) {
	// 查找所有 call_expression
	callQuery := `(call_expression) @call`
	callMatches, err := ctx.Query(callQuery)
	if err != nil {
		return
	}

	for _, callMatch := range callMatches {
		callNode := callMatch.Node

		// 获取被调用的函数名
		funcName := d.getCalledFunctionName(ctx, callNode)
		if funcName == "" {
			continue
		}

		// 检查此调用是否在保护条件内
		protections := d.extractParamProtectionsFromCallSite(ctx, callNode, funcName)
		if len(protections) > 0 {
			d.mu.Lock()
			d.paramProtections[funcName] = append(d.paramProtections[funcName], protections...)
			d.mu.Unlock()
		}
	}
}

// getCalledFunctionName 获取被调用函数的名称
func (d *BufferOverflowDetector) getCalledFunctionName(ctx *core.AnalysisContext, callNode *sitter.Node) string {
	// call_expression 结构: function(arg1, arg2, ...)
	// child 0 是 function 引用
	for i := 0; i < int(core.SafeChildCount(callNode)); i++ {
		child := core.SafeChild(callNode, i)
		childType := core.SafeType(child)

		if childType == "identifier" || childType == "field_expression" {
			return ctx.GetSourceText(child)
		}
	}
	return ""
}

// extractParamProtectionsFromCallSite 从调用点提取参数保护信息
func (d *BufferOverflowDetector) extractParamProtectionsFromCallSite(ctx *core.AnalysisContext, callNode *sitter.Node, funcName string) []ParamProtection {
	var protections []ParamProtection

	// 向上遍历 AST，查找包含此调用的 if 语句
	current := callNode.Parent()
	checkedIfs := make(map[string]bool)

	for current != nil {
		if core.SafeType(current) == "if_statement" {
			ifID := d.getNodeID(current)
			if checkedIfs[ifID] {
				current = current.Parent()
				continue
			}
			checkedIfs[ifID] = true

			// 提取 if 语句的条件
			conditions := d.extractConditionFromIfStatement(ctx, current)
			if len(conditions) > 0 {
				// 检查条件是否涉及此调用的参数
				argProtections := d.matchConditionsToArguments(ctx, callNode, current, conditions, funcName)
				protections = append(protections, argProtections...)
			}
		}
		current = current.Parent()
	}

	return protections
}

// matchConditionsToArguments 将条件匹配到函数参数
func (d *BufferOverflowDetector) matchConditionsToArguments(ctx *core.AnalysisContext, callNode *sitter.Node, ifStmt *sitter.Node, conditions []PathCondition, funcName string) []ParamProtection {
	var protections []ParamProtection

	// 获取调用的参数列表
	args := d.getCallArguments(ctx, callNode)

	// 对于每个条件，检查是否涉及某个参数
	for _, condition := range conditions {
		// 检查调用是否在 if 分支内（保护）还是 else 分支内（未保护）
		isInIfBranch := d.isCallInProtectedBranch(ctx, callNode, ifStmt, condition)

		// 检查条件中的变量是否匹配某个参数
		for argIdx, arg := range args {
			argText := ctx.GetSourceText(arg)

			// 检查条件是否涉及此参数
			if d.conditionInvolvesVariable(condition, argText) {
				// 只记录在 if 分支内的保护（不在 else 分支内）
				if isInIfBranch && condition.IsSafe {
					protection := ParamProtection{
						FuncName:   funcName,
						ParamIndex: argIdx,
						Protection: condition,
						CallSite:   fmt.Sprintf("%s:%d", ctx.Unit.FilePath, int(callNode.StartPoint().Row)+1),
						ParamName:  argText,
					}
					protections = append(protections, protection)
				}
			}
		}
	}

	return protections
}

// conditionInvolvesVariable 检查条件是否涉及指定变量
func (d *BufferOverflowDetector) conditionInvolvesVariable(condition PathCondition, varName string) bool {
	// 检查条件的变量名
	if strings.Contains(condition.Expression, varName) {
		return true
	}

	// 检查条件中的 sizeof(varName)
	if strings.Contains(condition.Expression, "sizeof("+varName+")") {
		return true
	}

	// 检查 strlen(varName)
	if strings.Contains(condition.Expression, "strlen("+varName+")") {
		return true
	}

	return false
}

// collectConditionsInScope 在作用域内收集条件
func (d *BufferOverflowDetector) collectConditionsInScope(ctx *core.AnalysisContext, node *sitter.Node, funcName string) {
	if node == nil {
		return
	}

	nodeType := core.SafeType(node)

	// 查找 if 语句
	if nodeType == "if_statement" {
		conditions := d.extractConditionFromIfStatement(ctx, node)
		if len(conditions) > 0 {
			nodeID := d.getNodeID(node)
			d.mu.Lock()
			d.pathConditions[nodeID] = conditions
			d.mu.Unlock()
		}
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		d.collectConditionsInScope(ctx, child, funcName)
	}
}

// extractConditionFromIfStatement 从 if 语句中提取条件
func (d *BufferOverflowDetector) extractConditionFromIfStatement(ctx *core.AnalysisContext, ifStmt *sitter.Node) []PathCondition {
	var conditions []PathCondition

	// if_statement 的结构:
	// if (condition) { ... } else { ... }
	// 0: "if", 1: (parenthesized_expression condition), 2: { consequence }, 3: "else", 4: { alternative }

	childCount := core.SafeChildCount(ifStmt)
	if childCount < 2 {
		return conditions
	}

	// 获取条件表达式
	conditionNode := core.SafeChild(ifStmt, 1)
	if conditionNode == nil {
		return conditions
	}

	// 处理 parenthesized_expression
	// tree-sitter 的 parenthesized_expression 结构: 0:"(", 1:expression, 2:")"
	if core.SafeType(conditionNode) == "parenthesized_expression" && core.SafeChildCount(conditionNode) > 1 {
		conditionNode = core.SafeChild(conditionNode, 1)
	}

	if conditionNode == nil {
		return conditions
	}

	// 提取条件信息
	conditionText := ctx.GetSourceText(conditionNode)
	line := int(conditionNode.StartPoint().Row) + 1

	// 分析条件类型
	cond := d.analyzeConditionExpression(ctx, conditionNode, conditionText, line)
	if cond != nil {
		conditions = append(conditions, *cond)

		// 如果有 else 分支，添加取反的条件
		if childCount >= 5 && core.SafeType(core.SafeChild(ifStmt, 3)) == "else" {
			negatedCond := *cond
			negatedCond.Negated = true
			conditions = append(conditions, negatedCond)
		}
	}

	return conditions
}

// analyzeConditionExpression 分析条件表达式
func (d *BufferOverflowDetector) analyzeConditionExpression(ctx *core.AnalysisContext, node *sitter.Node, exprText string, line int) *PathCondition {
	nodeType := core.SafeType(node)

	// 二元表达式: a < b, a > b, a <= b, etc.
	if nodeType == "binary_expression" {
		return d.analyzeBinaryExpression(ctx, node, exprText, line)
	}

	// 逻辑表达式: a && b, a || b
	if nodeType == "logical_expression" {
		return d.analyzeLogicalExpression(ctx, node, exprText, line)
	}

	// 一元表达式: !a
	if nodeType == "unary_expression" {
		return d.analyzeUnaryExpression(ctx, node, exprText, line)
	}

	// 函数调用: strlen(x) < 10
	if nodeType == "call_expression" {
		return d.analyzeCallInCondition(ctx, node, exprText, line)
	}

	return nil
}

// analyzeBinaryExpression 分析二元表达式
func (d *BufferOverflowDetector) analyzeBinaryExpression(ctx *core.AnalysisContext, node *sitter.Node, exprText string, line int) *PathCondition {
	if core.SafeChildCount(node) < 3 {
		return nil
	}

	left := core.SafeChild(node, 0)
	opNode := core.SafeChild(node, 1)
	right := core.SafeChild(node, 2)

	if opNode == nil {
		return nil
	}

	operation := ctx.GetSourceText(opNode)

	// 只关心比较操作符
	if !d.isComparisonOperator(operation) {
		return nil
	}

	// 提取变量名和值
	var variable string
	var value int64

	// 从右操作数提取常量值
	rightType := core.SafeType(right)
	if rightType == "number_literal" {
		if val, err := strconv.ParseInt(ctx.GetSourceText(right), 0, 64); err == nil {
			value = val
		}
	}

	// 从左操作数提取变量名
	leftType := core.SafeType(left)
	if leftType == "identifier" {
		variable = ctx.GetSourceText(left)
	}

	// 检查是否为保护性条件
	isSafe := d.isProtectionCondition(exprText, operation, variable, value)

	return &PathCondition{
		Node:       node,
		Variable:   variable,
		Operation:  operation,
		Value:      value,
		Expression: exprText,
		IsSafe:     isSafe,
		Negated:    false,
		Line:       line,
	}
}

// analyzeLogicalExpression 分析逻辑表达式
func (d *BufferOverflowDetector) analyzeLogicalExpression(ctx *core.AnalysisContext, node *sitter.Node, exprText string, line int) *PathCondition {
	// 简化处理：逻辑表达式作为整体条件
	return &PathCondition{
		Node:       node,
		Operation:  "&&",
		Expression: exprText,
		IsSafe:     d.isProtectionCondition(exprText, "", "", 0),
		Line:       line,
	}
}

// analyzeUnaryExpression 分析一元表达式
func (d *BufferOverflowDetector) analyzeUnaryExpression(ctx *core.AnalysisContext, node *sitter.Node, exprText string, line int) *PathCondition {
	// 处理 !a 的情况
	if core.SafeChildCount(node) >= 2 {
		opNode := core.SafeChild(node, 0)
		operand := core.SafeChild(node, 1)

		if opNode != nil && ctx.GetSourceText(opNode) == "!" {
			// 对内部表达式递归分析，然后标记为取反
			if innerCond := d.analyzeConditionExpression(ctx, operand, exprText, line); innerCond != nil {
				innerCond.Negated = !innerCond.Negated
				return innerCond
			}
		}
	}

	return nil
}

// analyzeCallInCondition 分析条件中的函数调用
func (d *BufferOverflowDetector) analyzeCallInCondition(ctx *core.AnalysisContext, node *sitter.Node, exprText string, line int) *PathCondition {
	// 提取函数名
	funcName := d.getCallFunctionName(ctx, node)

	// 特殊处理 strlen/sizeof 调用
	if funcName == "strlen" || funcName == "sizeof" {
		return &PathCondition{
			Node:       node,
			Operation:  "<=",
			Expression: exprText,
			IsSafe:     d.isProtectionCondition(exprText, "", "", 0),
			Line:       line,
		}
	}

	return nil
}

// isComparisonOperator 判断是否为比较操作符
func (d *BufferOverflowDetector) isComparisonOperator(op string) bool {
	switch op {
	case "<", ">", "<=", ">=", "==", "!=":
		return true
	}
	return false
}

// isProtectionCondition 判断是否为保护性条件
func (d *BufferOverflowDetector) isProtectionCondition(exprText, operation string, variable string, value int64) bool {
	// 简化处理：使用字符串匹配
	if strings.Contains(exprText, "strlen") && strings.Contains(exprText, "sizeof") {
		return true
	}
	if strings.Contains(exprText, "sizeof") && (operation == "<" || operation == "<=") {
		return true
	}
	if strings.Contains(exprText, "strlen") && (operation == "<" || operation == "<=") {
		return true
	}

	// 检查变量有上界约束
	if variable != "" && operation == "<" && value > 0 {
		return true
	}
	if variable != "" && operation == "<=" && value > 0 {
		return true
	}

	return false
}

// getNodeID 生成节点的唯一ID
func (d *BufferOverflowDetector) getNodeID(node *sitter.Node) string {
	return fmt.Sprintf("%p_%d", node, node.StartByte())
}

// ==================== P3: Z3 符号执行增强 ====================

// buildSymbolicState 构建符号状态（P3符号执行）
func (d *BufferOverflowDetector) buildSymbolicState(ctx *core.AnalysisContext, callNode *sitter.Node) *SymbolicState {
	state := &SymbolicState{
		Constraints: make([]BufferOverflowPathConstraint, 0),
		Variables:   make(map[string]int64),
		IsFeasible:  true,
	}

	// 向上遍历 AST，收集路径约束
	current := callNode.Parent()
	checkedIfs := make(map[string]bool)

	for current != nil {
		if core.SafeType(current) == "if_statement" {
			nodeID := d.getNodeID(current)
			if checkedIfs[nodeID] {
				current = current.Parent()
				continue
			}
			checkedIfs[nodeID] = true

			// 提取 if 语句的条件
			d.mu.RLock()
			conditions, exists := d.pathConditions[nodeID]
			d.mu.RUnlock()

			if exists {
				// 检查调用是否在 if 分支还是 else 分支
				isInIfBranch := d.isNodeInBranch(ctx, callNode, current, true)

				for _, cond := range conditions {
					// 将 PathCondition 转换为 PathConstraint
					constraint := BufferOverflowPathConstraint{
						Variable:   cond.Variable,
						Operator:   cond.Operation,
						Value:      cond.Value,
						Expression: cond.Expression,
						Line:       cond.Line,
					}

					// 根据调用所在分支调整约束
					if isInIfBranch {
						// if 分支：条件为真
						constraint.IsConjunct = true
					} else {
						// else 分支：条件为假，需要取反
						constraint.Operator = negateOperator(cond.Operation)
						constraint.IsDisjunct = true
					}

					state.Constraints = append(state.Constraints, constraint)

					// 提取变量值（如果能确定）
					if cond.Variable != "" && cond.Value > 0 {
						state.Variables[cond.Variable] = cond.Value
					}
				}
			}
		}
		current = current.Parent()
	}

	return state
}

// negateOperator 取反操作符（用于 else 分支）
func negateOperator(op string) string {
	negations := map[string]string{
		"<":  ">=",
		">":  "<=",
		"<=": ">",
		">=": "<",
		"==": "!=",
		"!=": "==",
	}
	if negated, ok := negations[op]; ok {
		return negated
	}
	return op
}

// isNodeInBranch 检查节点是否在指定分支中
func (d *BufferOverflowDetector) isNodeInBranch(ctx *core.AnalysisContext, node, ifStmt *sitter.Node, checkIfBranch bool) bool {
	childCount := core.SafeChildCount(ifStmt)
	if childCount < 3 {
		return false
	}

	// 获取 if 和 else 分支
	consequence := core.SafeChild(ifStmt, 2) // if 分支
	alternative := core.SafeChild(ifStmt, 4) // else 分支（如果存在）

	var targetBranch *sitter.Node
	if checkIfBranch {
		targetBranch = consequence
	} else {
		targetBranch = alternative
	}

	if targetBranch == nil {
		return false
	}

	// 检查节点是否在目标分支的子树中
	return d.isNodeInSubtree(node, targetBranch)
}

// isNodeInSubtree 递归检查节点是否在子树中
func (d *BufferOverflowDetector) isNodeInSubtree(node, subtree *sitter.Node) bool {
	if node == subtree {
		return true
	}

	for i := 0; i < int(core.SafeChildCount(subtree)); i++ {
		child := core.SafeChild(subtree, i)
		if d.isNodeInSubtree(node, child) {
			return true
		}
	}

	return false
}

// checkPathFeasibilityWithZ3 使用 Z3 检查路径可行性（P3）
func (d *BufferOverflowDetector) checkPathFeasibilityWithZ3(ctx *core.AnalysisContext, callNode *sitter.Node, dstName, srcName string) (isFeasible bool, reason string) {
	if d.z3Solver == nil || !d.z3Solver.IsAvailable() {
		// 没有 Z3，默认路径可行
		return true, ""
	}

	// 构建符号状态
	state := d.buildSymbolicState(ctx, callNode)
	if !state.IsFeasible {
		return false, state.Reason
	}

	// 检查约束是否矛盾
	if d.hasContradictoryConstraints(state) {
		return false, "Path has contradictory constraints (Z3 analysis)"
	}

	// 检查是否有保护性约束覆盖此操作
	if d.isOperationCoveredByProtection(state, dstName, srcName) {
		return false, "Operation is protected by path constraints (Z3 verified)"
	}

	return true, ""
}

// hasContradictoryConstraints 检查约束集合是否有矛盾
func (d *BufferOverflowDetector) hasContradictoryConstraints(state *SymbolicState) bool {
	// 收集每个变量的所有约束
	varConstraints := make(map[string][]BufferOverflowPathConstraint)
	for _, constraint := range state.Constraints {
		if constraint.Variable != "" {
			varConstraints[constraint.Variable] = append(varConstraints[constraint.Variable], constraint)
		}
	}

	// 检查每个变量的约束是否矛盾
	for _, constraints := range varConstraints {
		if d.constraintsConflict(constraints) {
			return true
		}
	}

	return false
}

// constraintsConflict 检查约束列表是否有冲突
func (d *BufferOverflowDetector) constraintsConflict(constraints []BufferOverflowPathConstraint) bool {
	for i := 0; i < len(constraints); i++ {
		for j := i + 1; j < len(constraints); j++ {
			c1, c2 := constraints[i], constraints[j]

			// 检查明显矛盾的约束
			// 例如: x < 10 和 x > 20
			if d.areConflictingConstraints(c1, c2) {
				return true
			}
		}
	}
	return false
}

// areConflictingConstraints 检查两个约束是否冲突
func (d *BufferOverflowDetector) areConflictingConstraints(c1, c2 BufferOverflowPathConstraint) bool {
	// 检查 x < a 和 x > b 类型，其中 a <= b
	if (c1.Operator == "<" && c2.Operator == ">") || (c1.Operator == ">" && c2.Operator == "<") {
		if c1.Value <= c2.Value {
			return true
		}
	}

	// 检查 x <= a 和 x >= b 类型，其中 a < b
	if (c1.Operator == "<=" && c2.Operator == ">=") || (c1.Operator == ">=" && c2.Operator == "<=") {
		if c1.Value < c2.Value {
			return true
		}
	}

	// 检查 x == a 和 x == b，其中 a != b
	if c1.Operator == "==" && c2.Operator == "==" && c1.Value != c2.Value {
		return true
	}

	// 检查 x == a 和 x != b，其中 a == b
	if (c1.Operator == "==" && c2.Operator == "!=") || (c1.Operator == "!=" && c2.Operator == "==") {
		if c1.Value == c2.Value {
			return true
		}
	}

	return false
}

// isOperationCoveredByProtection 检查操作是否被保护约束覆盖
func (d *BufferOverflowDetector) isOperationCoveredByProtection(state *SymbolicState, dstName, srcName string) bool {
	for _, constraint := range state.Constraints {
		// 检查约束是否涉及目标缓冲区或源
		if strings.Contains(constraint.Expression, dstName) || (srcName != "" && strings.Contains(constraint.Expression, srcName)) {
			// 检查是否为保护性约束
			if d.isProtectiveConstraint(constraint) {
				return true
			}
		}
	}
	return false
}

// isProtectiveConstraint 检查约束是否为保护性约束
func (d *BufferOverflowDetector) isProtectiveConstraint(constraint BufferOverflowPathConstraint) bool {
	// 检查是否为上界约束（保护性）
	if constraint.Operator == "<" || constraint.Operator == "<=" {
		return true
	}

	// 检查是否为 strlen/sizeof 保护
	if strings.Contains(constraint.Expression, "strlen") || strings.Contains(constraint.Expression, "sizeof") {
		return true
	}

	return false
}

// checkPathProtection 检查危险调用是否被路径条件保护
func (d *BufferOverflowDetector) checkPathProtection(ctx *core.AnalysisContext, callNode *sitter.Node, dstName, srcName string) (isProtected bool, protection string) {
	// 【阶段2-P2新增】首先检查参数保护（跨过程分析）
	// 如果 dstName 是函数参数，检查调用点是否有保护
	if paramProtected, paramProt := d.checkParameterProtectionAtCallSite(ctx, callNode, dstName); paramProtected {
		return true, paramProt
	}

	// 然后检查本地路径保护（原有逻辑）
	// 向上遍历 AST，查找包含此调用的 if 语句
	current := callNode
	checkedIfs := make(map[string]bool)

	for current != nil {
		parent := current.Parent()
		if parent == nil {
			break
		}

		parentType := core.SafeType(parent)

		// 找到 if 语句
		if parentType == "if_statement" {
			nodeID := d.getNodeID(parent)

			// 避免重复检查同一个 if
			if checkedIfs[nodeID] {
				current = parent
				continue
			}
			checkedIfs[nodeID] = true

			// 获取此 if 语句的条件
			d.mu.RLock()
			conditions, exists := d.pathConditions[nodeID]
			d.mu.RUnlock()

			if exists {
				for _, cond := range conditions {
					// 检查条件是否涉及目标缓冲区或源
					if d.conditionProtectsOperation(cond, dstName, srcName) {
						// 检查调用是否在正确的分支中
						if d.isCallInProtectedBranch(ctx, callNode, parent, cond) {
							return true, fmt.Sprintf("Protected by condition at line %d: %s", cond.Line, cond.Expression)
						}
					}
				}
			}
		}

		current = parent
	}

	// 【阶段2-P3新增】使用 Z3 进行路径可行性检查
	// 如果路径不可行或有矛盾约束，不报告漏洞
	if pathFeasible, reason := d.checkPathFeasibilityWithZ3(ctx, callNode, dstName, srcName); !pathFeasible {
		// 路径不可行或被保护约束覆盖
		return true, fmt.Sprintf("Path analysis: %s", reason)
	}

	return false, ""
}

// checkParameterProtectionAtCallSite 检查参数在调用点是否有保护（P2跨过程分析）
func (d *BufferOverflowDetector) checkParameterProtectionAtCallSite(ctx *core.AnalysisContext, callNode *sitter.Node, varName string) (isProtected bool, protection string) {
	// 获取当前函数名
	currentFuncName := d.getFunctionForNode(ctx, callNode)
	if currentFuncName == "" {
		return false, ""
	}

	// 获取函数定义的参数列表
	funcDef := d.findFunctionDefinition(ctx, currentFuncName)
	if funcDef == nil {
		return false, ""
	}

	// 查找变量名对应的参数索引
	paramIndex := d.findParameterIndex(ctx, funcDef, varName)
	if paramIndex < 0 {
		return false, ""
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// 查找此函数的参数保护
	if paramProts, exists := d.paramProtections[currentFuncName]; exists {
		for _, paramProt := range paramProts {
			// 仅检查参数索引是否匹配（P2简化逻辑：按位置匹配）
			if paramProt.ParamIndex == paramIndex {
				return true, fmt.Sprintf("Parameter %d protected at call site %s: %s",
					paramIndex, paramProt.CallSite, paramProt.Protection.Expression)
			}
		}
	}

	return false, ""
}

// findFunctionDefinition 查找函数定义
func (d *BufferOverflowDetector) findFunctionDefinition(ctx *core.AnalysisContext, funcName string) *sitter.Node {
	// 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, err := ctx.Query(funcQuery)
	if err != nil {
		return nil
	}

	for _, funcMatch := range funcMatches {
		name := d.extractFuncName(ctx, funcMatch.Node)
		if name == funcName {
			return funcMatch.Node
		}
	}

	return nil
}

// findParameterIndex 查找变量名在函数参数列表中的索引
func (d *BufferOverflowDetector) findParameterIndex(ctx *core.AnalysisContext, funcDef *sitter.Node, varName string) int {
	// function_declarator 的结构:
	// 0: identifier (函数名)
	// 1: parameter_list

	for i := 0; i < int(core.SafeChildCount(funcDef)); i++ {
		child := core.SafeChild(funcDef, i)
		if core.SafeType(child) == "function_declarator" {
			// 查找 parameter_list
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				paramChild := core.SafeChild(child, j)
				if core.SafeType(paramChild) == "parameter_list" {
					// 遍历参数
					for k := 0; k < int(core.SafeChildCount(paramChild)); k++ {
						param := core.SafeChild(paramChild, k)
						paramType := core.SafeType(param)

						// 跳过逗号和括号
						if paramType == "," || paramType == "(" || paramType == ")" {
							continue
						}

						// 提取参数名
						paramName := d.extractParameterName(ctx, param)
						if paramName == varName {
							return k // 返回参数索引
						}
					}
					break
				}
			}
			break
		}
	}

	return -1
}

// extractParameterName 提取参数名
func (d *BufferOverflowDetector) extractParameterName(ctx *core.AnalysisContext, paramNode *sitter.Node) string {
	// parameter_decl 节点结构
	// 可能是: "int size" 或 "char* dst"

	// 递归查找 identifier
	var extractIdentifier func(node *sitter.Node) string
	extractIdentifier = func(node *sitter.Node) string {
		if node == nil {
			return ""
		}

		nodeType := core.SafeType(node)
		if nodeType == "identifier" {
			return ctx.GetSourceText(node)
		}

		// 递归子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if name := extractIdentifier(child); name != "" {
				return name
			}
		}

		return ""
	}

	return extractIdentifier(paramNode)
}

// isFunctionParameter 检查标识符是否为函数参数
func (d *BufferOverflowDetector) isFunctionParameter(ctx *core.AnalysisContext, node *sitter.Node, varName string) bool {
	if node == nil {
		return false
	}

	// 获取包含当前节点的函数定义
	funcNode := d.getContainingFunctionNode(ctx, node)
	if funcNode == nil {
		return false
	}

	// 查找函数参数列表
	// function_definition 结构: [type, declarator, body, ...]
	// 参数列表通常在 declarator 的 parameter_list 中
	parameters := d.extractFunctionParameters(ctx, funcNode)
	if parameters == nil {
		return false
	}

	// 检查 varName 是否在参数列表中
	for _, paramName := range parameters {
		if paramName == varName {
			return true
		}
	}

	return false
}

// getContainingFunctionNode 获取包含指定节点的函数定义节点
func (d *BufferOverflowDetector) getContainingFunctionNode(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
	current := node.Parent()
	visited := make(map[uintptr]bool)

	for current != nil {
		nodeID := current.ID()
		if visited[nodeID] {
			break
		}
		visited[nodeID] = true

		nodeType := core.SafeType(current)
		if nodeType == "function_definition" {
			return current
		}

		current = current.Parent()
	}

	return nil
}

// extractFunctionParameters 从函数定义中提取参数名列表
func (d *BufferOverflowDetector) extractFunctionParameters(ctx *core.AnalysisContext, funcNode *sitter.Node) []string {
	if funcNode == nil {
		return nil
	}

	// function_definition 结构: [type, declarator, body, ...]
	// declarator 可能包含 parameter_list
	var findParameterList func(node *sitter.Node) *sitter.Node
	findParameterList = func(node *sitter.Node) *sitter.Node {
		if node == nil {
			return nil
		}

		nodeType := core.SafeType(node)
		if nodeType == "parameter_list" {
			return node
		}

		// 递归子节点
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if result := findParameterList(child); result != nil {
				return result
			}
		}

		return nil
	}

	// 从函数定义的 declarator 部分开始查找
	if core.SafeChildCount(funcNode) > 1 {
		declarator := core.SafeChild(funcNode, 1) // function_declarator
		paramList := findParameterList(declarator)

		if paramList != nil {
			var parameters []string
			for i := 0; i < int(core.SafeChildCount(paramList)); i++ {
				paramDecl := core.SafeChild(paramList, i)
				if core.SafeType(paramDecl) == "parameter_declaration" {
					// 提取参数名
					if paramName := d.extractParameterName(ctx, paramDecl); paramName != "" {
						parameters = append(parameters, paramName)
					}
				}
			}
			return parameters
		}
	}

	return nil
}

// conditionProtectsOperation 检查条件是否保护该操作
func (d *BufferOverflowDetector) conditionProtectsOperation(cond PathCondition, dstName, srcName string) bool {
	// 条件涉及目标缓冲区
	if strings.Contains(cond.Expression, dstName) {
		return true
	}

	// 条件涉及源
	if srcName != "" && strings.Contains(cond.Expression, srcName) {
		return true
	}

	// 条件包含 strlen/sizeof（可能是通用保护）
	if strings.Contains(cond.Expression, "strlen") || strings.Contains(cond.Expression, "sizeof") {
		return true
	}

	return false
}

// isCallInProtectedBranch 检查调用是否在受保护的分支中
func (d *BufferOverflowDetector) isCallInProtectedBranch(ctx *core.AnalysisContext, callNode, ifStmt *sitter.Node, cond PathCondition) bool {
	// if 语句的结构:
	// if (condition) { consequence } else { alternative }
	// 0: "if", 1: (condition), 2: { consequence }, 3: "else", 4: { alternative }

	consequence := core.SafeChild(ifStmt, 2)
	alternative := core.SafeChild(ifStmt, 4)

	// 如果条件被取反，保护逻辑也相反
	if cond.Negated {
		// 条件取反时，else 分支是受保护的
		if alternative != nil && d.isNodeInSubtree(callNode, alternative) {
			return true
		}
	} else {
		// 条件正常时，then 分支是受保护的
		if consequence != nil && d.isNodeInSubtree(callNode, consequence) {
			return true
		}
	}

	return false
}

// ==================== 阶段2-P1改进：动态分配缓冲区识别 ====================

// collectDynamicAllocations 收集所有动态分配信息
func (d *BufferOverflowDetector) collectDynamicAllocations(ctx *core.AnalysisContext) {
	// 1. 查找所有赋值表达式，识别 malloc/calloc/realloc 调用
	assignQuery := `(assignment_expression) @assign`
	assignMatches, err := ctx.Query(assignQuery)
	if err == nil {
		for _, match := range assignMatches {
			d.analyzeAssignmentForAllocation(ctx, match.Node)
		}
	}

	// 2. 查找所有声明语句中的初始化器
	// declaration: type var = init
	declQuery := `(declaration) @decl`
	declMatches, err := ctx.Query(declQuery)
	if err == nil {
		for _, match := range declMatches {
			d.analyzeDeclarationForAllocation(ctx, match.Node)
		}
	}
}

// analyzeAssignmentForAllocation 分析赋值表达式，识别动态分配
func (d *BufferOverflowDetector) analyzeAssignmentForAllocation(ctx *core.AnalysisContext, assignNode *sitter.Node) {
	if assignNode == nil || core.SafeChildCount(assignNode) < 3 {
		return
	}

	// assignment_expression 结构: left = right
	// 找到左操作数（被赋值的变量）
	left := core.SafeChild(assignNode, 0)
	if left == nil || core.SafeType(left) != "identifier" {
		return
	}

	varName := ctx.GetSourceText(left)

	// 找到右操作数（可能是 malloc 调用）
	right := core.SafeChild(assignNode, 2)
	if right == nil {
		return
	}

	// 检查是否为函数调用
	if core.SafeType(right) != "call_expression" {
		return
	}

	funcName := d.getCallFunctionName(ctx, right)
	if funcName != "malloc" && funcName != "calloc" && funcName != "realloc" {
		return
	}

	// 提取分配大小
	sizeExpr, sizeVar, isSizeOfSrc := d.extractAllocationSize(ctx, right, funcName)
	if sizeExpr == "" {
		return
	}

	line := int(assignNode.StartPoint().Row) + 1
	funcNameCtx := d.getContainingFunctionName(ctx, assignNode)

	alloc := &DynamicAllocation{
		VarName:     varName,
		AllocType:   funcName,
		SizeExpr:    sizeExpr,
		SizeVar:     sizeVar,
		LineNumber:  line,
		FuncName:    funcNameCtx,
		IsSizeOfSrc: isSizeOfSrc,
	}

	d.mu.Lock()
	d.dynamicAllocations[varName] = alloc
	d.allocSizeExprs[varName] = sizeExpr
	d.mu.Unlock()
}

// analyzeDeclarationForAllocation 分析声明语句，识别动态分配
func (d *BufferOverflowDetector) analyzeDeclarationForAllocation(ctx *core.AnalysisContext, declNode *sitter.Node) {
	if declNode == nil {
		return
	}

	// 遍历声明节点的子节点，查找声明符和初始化器
	var declarator *sitter.Node
	var initExpr *sitter.Node

	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		childType := core.SafeType(child)

		// 查找声明符（变量名）
		if childType == "declarator" || childType == "init_declarator" || childType == "pointer_declarator" {
			// 首先检查是否是指针声明符（如 char* dst）
			if childType == "pointer_declarator" {
				// pointer_declarator 的子节点包含 identifier
				for j := 0; j < int(core.SafeChildCount(child)); j++ {
					grandChild := core.SafeChild(child, j)
					if core.SafeType(grandChild) == "identifier" {
						declarator = grandChild
					}
					if core.SafeType(grandChild) == "call_expression" {
						initExpr = grandChild
					}
				}
			} else {
				// init_declarator 或 declarator
				for j := 0; j < int(core.SafeChildCount(child)); j++ {
					grandChild := core.SafeChild(child, j)
					gcType := core.SafeType(grandChild)

					if gcType == "identifier" {
						declarator = grandChild
					}
					// 检查是否嵌套的 pointer_declarator
					if gcType == "pointer_declarator" {
						for k := 0; k < int(core.SafeChildCount(grandChild)); k++ {
							greatGrandChild := core.SafeChild(grandChild, k)
							if core.SafeType(greatGrandChild) == "identifier" {
								declarator = greatGrandChild
							}
						}
					}
					// 查找初始化表达式
					if gcType == "=" || gcType == "call_expression" {
						if gcType == "=" {
							// 下一个兄弟节点是初始化值
							if j+1 < int(core.SafeChildCount(child)) {
								nextChild := core.SafeChild(child, j+1)
								initExpr = nextChild
							}
						} else if gcType == "call_expression" {
							initExpr = grandChild
						}
					}
				}
			}
		}
	}

	if declarator == nil {
		return
	}

	if initExpr == nil {
		return
	}

	varName := ctx.GetSourceText(declarator)

	// 检查初始化表达式的类型
	initExprType := core.SafeType(initExpr)
	if initExprType == "call_expression" {
		// 直接的函数调用
		funcName := d.getCallFunctionName(ctx, initExpr)

		if funcName != "malloc" && funcName != "calloc" && funcName != "realloc" {
			return
		}

		// 提取分配大小
		sizeExpr, sizeVar, isSizeOfSrc := d.extractAllocationSize(ctx, initExpr, funcName)
		if sizeExpr == "" {
			return
		}

		line := int(declNode.StartPoint().Row) + 1
		funcNameCtx := d.getContainingFunctionName(ctx, declNode)

		alloc := &DynamicAllocation{
			VarName:     varName,
			AllocType:   funcName,
			SizeExpr:    sizeExpr,
			SizeVar:     sizeVar,
			LineNumber:  line,
			FuncName:    funcNameCtx,
			IsSizeOfSrc: isSizeOfSrc,
		}

		d.mu.Lock()
		d.dynamicAllocations[varName] = alloc
		d.allocSizeExprs[varName] = sizeExpr
		d.mu.Unlock()
	} else if initExprType == "cast_expression" {
		// 类型转换表达式：(char*)malloc(...)
		// 需要找到内部的 call_expression

		// 递归查找 call_expression
		var callExpr *sitter.Node
		d.findCallExpressionInSubtree(initExpr, &callExpr)

		if callExpr != nil {
			funcName := d.getCallFunctionName(ctx, callExpr)

			if funcName != "malloc" && funcName != "calloc" && funcName != "realloc" {
				return
			}

			// 提取分配大小
			sizeExpr, sizeVar, isSizeOfSrc := d.extractAllocationSize(ctx, callExpr, funcName)
			if sizeExpr == "" {
				return
			}

			line := int(declNode.StartPoint().Row) + 1
			funcNameCtx := d.getContainingFunctionName(ctx, declNode)

			alloc := &DynamicAllocation{
				VarName:     varName,
				AllocType:   funcName,
				SizeExpr:    sizeExpr,
				SizeVar:     sizeVar,
				LineNumber:  line,
				FuncName:    funcNameCtx,
				IsSizeOfSrc: isSizeOfSrc,
			}

			d.mu.Lock()
			d.dynamicAllocations[varName] = alloc
			d.allocSizeExprs[varName] = sizeExpr
			d.mu.Unlock()
		}
	} else {
		return
	}
}

// findCallExpressionInSubtree 在子树中递归查找 call_expression
func (d *BufferOverflowDetector) findCallExpressionInSubtree(node *sitter.Node, result **sitter.Node) {
	if node == nil || *result != nil {
		return
	}

	if core.SafeType(node) == "call_expression" {
		*result = node
		return
	}

	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		d.findCallExpressionInSubtree(child, result)
	}
}

// extractAllocationSize 提取分配大小表达式
func (d *BufferOverflowDetector) extractAllocationSize(ctx *core.AnalysisContext, callNode *sitter.Node, funcName string) (sizeExpr, sizeVar string, isSizeOfSrc bool) {
	// 获取参数列表
	args := d.getCallArguments(ctx, callNode)
	if len(args) == 0 {
		return
	}

	var sizeArg *sitter.Node
	switch funcName {
	case "malloc", "realloc":
		// malloc(size), realloc(ptr, size)
		sizeArgIndex := 0
		if funcName == "realloc" && len(args) > 1 {
			sizeArgIndex = 1
		}
		if len(args) > sizeArgIndex {
			sizeArg = args[sizeArgIndex]
		}
	case "calloc":
		// calloc(count, size) - 总大小是 count * size
		if len(args) >= 2 {
			// 简化：只检查 size 参数
			sizeArg = args[1]
		}
	}

	if sizeArg == nil {
		return
	}

	sizeExpr = ctx.GetSourceText(sizeArg)
	sizeExpr = strings.TrimSpace(sizeExpr)

	// 检查是否基于源大小
	// 模式1: strlen(src) + 1
	// 模式2: sizeof(src)
	if strings.Contains(sizeExpr, "strlen") || strings.Contains(sizeExpr, "sizeof") {
		isSizeOfSrc = true
		// 提取变量名
		if strings.Contains(sizeExpr, "strlen(") {
			start := strings.Index(sizeExpr, "strlen(") + 7
			end := strings.Index(sizeExpr[start:], ")")
			if end > 0 {
				sizeVar = strings.TrimSpace(sizeExpr[start : start+end])
			}
		} else if strings.Contains(sizeExpr, "sizeof(") {
			start := strings.Index(sizeExpr, "sizeof(") + 7
			end := strings.Index(sizeExpr[start:], ")")
			if end > 0 {
				sizeVar = strings.TrimSpace(sizeExpr[start : start+end])
			}
		}
	}

	return sizeExpr, sizeVar, isSizeOfSrc
}

// getContainingFunctionName 获取包含节点的函数名
func (d *BufferOverflowDetector) getContainingFunctionName(ctx *core.AnalysisContext, node *sitter.Node) string {
	current := node
	for current != nil {
		if core.SafeType(current) == "function_definition" {
			// 提取函数名
			for i := 0; i < int(core.SafeChildCount(current)); i++ {
				child := core.SafeChild(current, i)
				if core.SafeType(child) == "function_declarator" {
					// function_declarator 的子节点包含函数名
					for j := 0; j < int(core.SafeChildCount(child)); j++ {
						grandChild := core.SafeChild(child, j)
						if core.SafeType(grandChild) == "identifier" {
							return ctx.GetSourceText(grandChild)
						}
					}
				}
			}
		}
		current = current.Parent()
	}
	return ""
}

// isDynamicAllocatedSafe 检查动态分配的目标缓冲区是否安全
func (d *BufferOverflowDetector) isDynamicAllocatedSafe(ctx *core.AnalysisContext, dstName, srcName string) (isSafe bool, reason string) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	alloc, exists := d.dynamicAllocations[dstName]

	if !exists {
		return false, ""
	}

	// 如果分配大小基于源大小（如 malloc(strlen(src)+1)），则是安全的
	if alloc.IsSizeOfSrc {
		// 检查源变量是否匹配
		if alloc.SizeVar == srcName || alloc.SizeVar == "" {
			return true, fmt.Sprintf("Dynamic allocation based on source size at line %d", alloc.LineNumber)
		}
	}

	// 如果是 malloc(常量)，需要检查常量是否足够大
	// 这里简化处理：如果有 +1，认为考虑了 null 终止符
	if strings.Contains(alloc.SizeExpr, "+1") || strings.Contains(alloc.SizeExpr, "+ 1") {
		return true, fmt.Sprintf("Dynamic allocation with null terminator at line %d", alloc.LineNumber)
	}

	return false, ""
}
