package detectors

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"

	"gosast/internal/core"
)

// HeapObjectWithTaint 带污点信息的堆对象
type HeapObjectWithTaint struct {
	*HeapObject
	IsTainted   bool     // 是否被用户输入污染
	TaintPath   []string // 污点路径描述
	IsSizeExpr  bool     // 大小是否为表达式（需要 Z3 求解）
	SizeExpr    string   // 大小表达式文本
	Constraints []string // 约束条件（如 "len > 0", "len < 100"）
}

// HeapObject 表示一个堆分配的对象
type HeapObject struct {
	// 变量名
	VarName string
	// 分配的大小（字节）
	Size int64
	// 分配函数（malloc, calloc, realloc）
	AllocFunc string
	// 分配行号
	Line int
	// 所在函数
	Function string
	// 是否是数组类型
	IsArray bool
	// 数组元素大小（用于 calloc）
	ElementSize int64
	// 分配节点
	AllocNode *sitter.Node
	// 污点相关字段
	IsTainted  bool     // 大小是否被用户输入污染
	TaintPath  []string // 污点传播路径描述
	IsSizeExpr bool     // 大小是否为表达式（非常量）
	SizeExpr   string   // 大小表达式文本
}

// HeapObjectModel 堆对象模型
type HeapObjectModel struct {
	// 函数名 -> 堆对象列表
	// key: functionName:varName
	objects map[string]*HeapObject
	mu      sync.RWMutex // 【修复】添加锁保护并发访问
}

// NewHeapObjectModel 创建堆对象模型
func NewHeapObjectModel() *HeapObjectModel {
	return &HeapObjectModel{
		objects: make(map[string]*HeapObject),
	}
}

// AddObject 添加堆对象
func (m *HeapObjectModel) AddObject(funcName, varName string, obj *HeapObject) {
	key := funcName + ":" + varName
	obj.VarName = varName
	obj.Function = funcName
	// 【修复】使用写锁保护
	m.mu.Lock()
	m.objects[key] = obj
	m.mu.Unlock()
}

// GetObject 获取堆对象
func (m *HeapObjectModel) GetObject(funcName, varName string) *HeapObject {
	key := funcName + ":" + varName
	// 【修复】使用读锁保护
	m.mu.RLock()
	obj := m.objects[key]
	m.mu.RUnlock()
	return obj
}

// GetObjectInAnyScope 在任何作用域中查找堆对象（优先当前函数）
func (m *HeapObjectModel) GetObjectInAnyScope(varName string, currentFunc string) *HeapObject {
	// 【修复】使用读锁保护
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. 优先查找当前函数中的变量
	currentFuncKey := currentFunc + ":" + varName
	if obj, ok := m.objects[currentFuncKey]; ok {
		return obj
	}

	// 2. 如果当前函数中没有，查找其他函数中的变量（用于跨函数分析）
	for key, obj := range m.objects {
		if strings.HasSuffix(key, ":"+varName) {
			return obj
		}
	}
	return nil
}

// GetAllObjects 获取所有堆对象
func (m *HeapObjectModel) GetAllObjects() []*HeapObject {
	// 【修复】使用读锁保护
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*HeapObject, 0, len(m.objects))
	for _, obj := range m.objects {
		result = append(result, obj)
	}
	return result
}

// HeapOverflowDetector 堆溢出检测器
type HeapOverflowDetector struct {
	*core.BaseDetector
	// 堆对象模型
	heapModel *HeapObjectModel
	// 污点分析引擎
	taintEngine *core.MemoryTaintEngine
	// 分析上下文（用于获取源文本）
	analysisCtx *core.AnalysisContext
	// Z3 约束求解器
	z3Solver core.Z3Solver
}

// NewHeapOverflowDetector 创建检测器
func NewHeapOverflowDetector() *HeapOverflowDetector {
	return &HeapOverflowDetector{
		BaseDetector: core.NewBaseDetector("Heap Overflow Detector", "Detects heap buffer overflows using cross-procedural analysis with taint and Z3"),
		heapModel:    NewHeapObjectModel(),
		taintEngine:  nil, // 在 Run 方法中初始化（需要 AnalysisContext）
		z3Solver:     nil, // 在需要时创建
	}
}

// Run 运行检测器
func (d *HeapOverflowDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 保存分析上下文
	d.analysisCtx = ctx

	// 0. 初始化 Z3 约束求解器（延迟创建，在需要时使用）
	if d.z3Solver == nil {
		if solver, err := core.CreateZ3Solver(); err == nil {
			d.z3Solver = solver
			defer d.z3Solver.Close()
		}
	}

	// 1. 初始化污点分析引擎
	if d.taintEngine == nil {
		d.taintEngine = core.NewMemoryTaintEngine(ctx)
	}

	// 执行污点传播分析
	if ctx.CFG == nil || ctx.CFG.Entry == nil {
		// CFG is empty, this is ok for single-file analysis
	} else if err := d.taintEngine.Propagate(ctx.CFG); err != nil {
	}

	// 1. 收集所有堆对象（跨函数）
	d.collectHeapObjects(ctx)

	// 2. 执行跨过程分析
	d.performCrossProceduralAnalysis(ctx)

	// 3. 检测危险操作
	dangerousOps := d.findDangerousOperations(ctx)

	// 4. 分析每个危险操作
	for _, op := range dangerousOps {
		if vuln := d.analyzeDangerousOperation(ctx, op); vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	return vulns, nil
}

// collectHeapObjects 收集所有堆对象
func (d *HeapOverflowDetector) collectHeapObjects(ctx *core.AnalysisContext) {
	// 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, err := ctx.Query(funcQuery)
	if err != nil {
		return
	}

	for _, funcMatch := range funcMatches {
		funcName := d.extractFunctionName(ctx, funcMatch.Node)
		if funcName == "" {
			continue
		}

		// 收集该函数中的堆对象
		d.collectHeapObjectsInFunction(ctx, funcMatch.Node, funcName)
	}
}

// collectHeapObjectsInFunction 在函数中收集堆对象
func (d *HeapOverflowDetector) collectHeapObjectsInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, funcName string) {

	// 查找函数体（compound_statement）
	var funcBody *sitter.Node
	for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
		child := core.SafeChild(funcNode, i)
		if core.SafeType(child) == "compound_statement" {
			funcBody = child
			break
		}
	}

	if funcBody == nil {
		return
	}

	// 查找所有声明和赋值
	query := `(declaration) @decl`
	declMatches, _ := ctx.Query(query)

	// 过滤出在当前函数作用域内的声明
	var filteredDecls []*sitter.Node
	for _, match := range declMatches {
		if d.isNodeInFunction(match.Node, funcBody) {
			filteredDecls = append(filteredDecls, match.Node)
		}
	}

	for _, declNode := range filteredDecls {
		d.extractHeapObjectFromDecl(ctx, declNode, funcName, funcNode)
	}

	// 查找赋值表达式
	assignQuery := `(assignment_expression) @assign`
	assignMatches, _ := ctx.Query(assignQuery)

	// 过滤出在当前函数作用域内的赋值表达式
	var filteredAssigns []*sitter.Node
	for _, match := range assignMatches {
		if d.isNodeInFunction(match.Node, funcBody) {
			filteredAssigns = append(filteredAssigns, match.Node)
		}
	}

	for _, assignNode := range filteredAssigns {
		d.extractHeapObjectFromAssignment(ctx, assignNode, funcName, funcNode)
	}
}

// extractHeapObjectFromDecl 从声明中提取堆对象
func (d *HeapOverflowDetector) extractHeapObjectFromDecl(ctx *core.AnalysisContext, declNode *sitter.Node, funcName string, funcNode *sitter.Node) {
	// 【改进】过滤掉 static 数组和非堆分配的声明
	// 递归检查声明是否包含 static 或 array_declarator
	if d.hasStaticOrArrayDeclarator(ctx, declNode) {
		return
	}

	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if core.SafeType(child) == "init_declarator" {
			d.extractHeapObjectFromInitDeclarator(ctx, child, funcName, funcNode)
		}
	}
}

// hasStaticOrArrayDeclarator 递归检查声明是否包含 static 或 array_declarator
func (d *HeapOverflowDetector) hasStaticOrArrayDeclarator(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	nodeType := core.SafeType(node)

	// 检查是否是 storage_class_specifier (static)
	if nodeType == "storage_class_specifier" {
		text := ctx.GetSourceText(node)
		if text == "static" {
			return true
		}
	}

	// 检查是否是 array_declarator
	if nodeType == "array_declarator" {
		return true
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		childType := core.SafeType(child)

		// 跳过某些不需要递归的节点类型以提高性能
		if childType == "comment" || childType == "string_literal" {
			continue
		}

		if d.hasStaticOrArrayDeclarator(ctx, child) {
			return true
		}
	}

	return false
}

// extractHeapObjectFromAssignment 从赋值表达式中提取堆对象
func (d *HeapOverflowDetector) extractHeapObjectFromAssignment(ctx *core.AnalysisContext, assignNode *sitter.Node, funcName string, funcNode *sitter.Node) {
	if core.SafeChildCount(assignNode) < 3 {
		return
	}

	left := core.SafeChild(assignNode, 0)
	right := core.SafeChild(assignNode, 2)

	varName := ctx.GetSourceText(left)

	// 检查右边是否是堆分配函数
	heapObj := d.analyzeHeapAllocationExpr(ctx, right, varName, funcName, funcNode)
	if heapObj != nil {
		d.heapModel.AddObject(funcName, varName, heapObj)
	}
}

// extractHeapObjectFromInitDeclarator 从初始化声明符中提取堆对象
func (d *HeapOverflowDetector) extractHeapObjectFromInitDeclarator(ctx *core.AnalysisContext, initDecl *sitter.Node, funcName string, funcNode *sitter.Node) {
	// 提取变量名
	varName := d.extractDeclaratorName(ctx, initDecl)
	if varName == "" {
		return
	}

	// 查找初始化值
	initValue := d.findInitDeclaratorValue(initDecl)
	if initValue == nil {
		return
	}

	// 分析堆分配表达式
	heapObj := d.analyzeHeapAllocationExpr(ctx, initValue, varName, funcName, funcNode)
	if heapObj != nil {
		d.heapModel.AddObject(funcName, varName, heapObj)
	}
}

// analyzeHeapAllocationExpr 分析堆分配表达式
func (d *HeapOverflowDetector) analyzeHeapAllocationExpr(ctx *core.AnalysisContext, expr *sitter.Node, varName, funcName string, funcNode *sitter.Node) *HeapObject {
	// 如果是 cast_expression，递归检查子节点
	if core.SafeType(expr) == "cast_expression" && core.SafeChildCount(expr) >= 2 {
		return d.analyzeHeapAllocationExpr(ctx, core.SafeChild(expr, 1), varName, funcName, funcNode)
	}

	// 如果是 call_expression
	if core.SafeType(expr) == "call_expression" {
		calledFuncName := d.extractCalledFunctionName(ctx, expr)

		// 检查是否是堆分配函数
		if calledFuncName == "malloc" {
			size, sizeArg, sizeExpr := d.extractMallocSizeWithNode(ctx, expr)

			// 增强的污点检查：对于标识符，查找其定义
			isTainted := false
			if d.taintEngine != nil {
				if core.SafeType(sizeArg) == "identifier" {
					// 使用增强的标识符污点检查
					isTainted = d.isIdentifierTainted(ctx, sizeArg, funcNode)
				} else {
					// 对于其他类型的表达式，使用直接检查
					isTainted = d.taintEngine.IsTainted(sizeArg)
				}
			}

			taintPath := d.extractTaintPath(sizeArg)

			// 为所有 malloc 调用创建堆对象（即使大小未知，也需要追踪）
			// 这样可以避免跨作用域的变量混淆
			line := int(expr.StartPoint().Row) + 1
			return &HeapObject{
				VarName:    varName,
				Size:       size,
				AllocFunc:  "malloc",
				Function:   funcName,
				Line:       line,
				AllocNode:  expr,
				IsTainted:  isTainted,
				TaintPath:  taintPath,
				IsSizeExpr: sizeExpr != "",
				SizeExpr:   sizeExpr,
			}
		} else if calledFuncName == "calloc" {
			count, elemSize := d.extractCallocSize(ctx, expr)
			if count > 0 && elemSize > 0 {
				size := count * elemSize
				line := int(expr.StartPoint().Row) + 1
				return &HeapObject{
					VarName:     varName,
					Size:        size,
					AllocFunc:   "calloc",
					Function:    funcName,
					IsArray:     true,
					ElementSize: elemSize,
					Line:        line,
					AllocNode:   expr,
				}
			}
		} else if calledFuncName == "realloc" {
			size := d.extractReallocSize(ctx, expr)
			if size > 0 {
				line := int(expr.StartPoint().Row) + 1
				return &HeapObject{
					VarName:   varName,
					Size:      size,
					AllocFunc: "realloc",
					Function:  funcName,
					Line:      line,
					AllocNode: expr,
				}
			}
		}
	}

	return nil
}

// extractMallocSize 提取 malloc 的大小
func (d *HeapOverflowDetector) extractMallocSize(ctx *core.AnalysisContext, callExpr *sitter.Node) int64 {
	size, _, _ := d.extractMallocSizeWithNode(ctx, callExpr)
	return size
}

// extractMallocSizeWithNode 提取 malloc 的大小，同时返回大小参数节点和表达式文本
func (d *HeapOverflowDetector) extractMallocSizeWithNode(ctx *core.AnalysisContext, callExpr *sitter.Node) (int64, *sitter.Node, string) {
	if core.SafeChildCount(callExpr) < 2 {
		return 0, nil, ""
	}

	// malloc(size) - 第二个子节点是 argument_list
	argList := core.SafeChild(callExpr, 1)

	if argList == nil || core.SafeType(argList) != "argument_list" {
		return 0, nil, ""
	}

	// argument_list 的子节点可能包含标点符号，需要找到实际的表达式
	// 结构通常是: "(" arg1 "," arg2 "," ... ")"
	// 所以实际参数在 child 1, 3, 5... 等位置
	if core.SafeChildCount(argList) < 2 {
		return 0, nil, ""
	}

	arg := core.SafeChild(argList, 1) // 跳过 "("
	if arg == nil {
		return 0, nil, ""
	}

	size := d.evaluateSizeExpression(ctx, arg)
	sizeExpr := ctx.GetSourceText(arg)

	return size, arg, sizeExpr
}

// extractTaintPath 提取节点的污点传播路径
func (d *HeapOverflowDetector) extractTaintPath(node *sitter.Node) []string {
	if d.taintEngine == nil || node == nil || d.analysisCtx == nil {
		return nil
	}

	taintSteps := d.taintEngine.GetTaintPath(node)
	if len(taintSteps) == 0 {
		return nil
	}

	var path []string
	for _, step := range taintSteps {
		// 获取节点文本用于更清晰的路径描述
		fromText := step.From.Type()
		toText := step.To.Type()
		if step.From != nil && d.analysisCtx != nil {
			if src := d.analysisCtx.GetSourceText(step.From); src != "" && len(src) < 50 {
				fromText = src
			}
		}
		if step.To != nil && d.analysisCtx != nil {
			if src := d.analysisCtx.GetSourceText(step.To); src != "" && len(src) < 50 {
				toText = src
			}
		}
		desc := fmt.Sprintf("%s -> %s (%s)", fromText, toText, step.Reason)
		path = append(path, desc)
	}
	return path
}

// extractCallocSize 提取 calloc 的大小和元素大小
func (d *HeapOverflowDetector) extractCallocSize(ctx *core.AnalysisContext, callExpr *sitter.Node) (int64, int64) {
	if core.SafeChildCount(callExpr) < 2 {
		return 0, 0
	}

	// calloc(count, elemSize) - 第二个子节点是 argument_list
	argList := core.SafeChild(callExpr, 1)
	if argList == nil || core.SafeType(argList) != "argument_list" {
		return 0, 0
	}

	// argument_list 的结构: "(" arg1 "," arg2 "," ... ")"
	// 参数在 child 1, 3, 5... 等位置
	if core.SafeChildCount(argList) < 4 {
		return 0, 0
	}

	countArg := core.SafeChild(argList, 1)    // 第一个参数
	elemSizeArg := core.SafeChild(argList, 3) // 第二个参数（跳过逗号）

	count := d.evaluateSizeExpression(ctx, countArg)
	elemSize := d.evaluateSizeExpression(ctx, elemSizeArg)

	return count, elemSize
}

// extractReallocSize 提取 realloc 的大小
func (d *HeapOverflowDetector) extractReallocSize(ctx *core.AnalysisContext, callExpr *sitter.Node) int64 {
	if core.SafeChildCount(callExpr) < 2 {
		return 0
	}

	// realloc(ptr, size) - 第二个子节点是 argument_list
	argList := core.SafeChild(callExpr, 1)
	if argList == nil || core.SafeType(argList) != "argument_list" {
		return 0
	}

	// argument_list 的结构: "(" ptr "," size ")"
	// 第二个参数在 child 3 的位置（跳过 "("、第一个参数、逗号）
	if core.SafeChildCount(argList) < 4 {
		return 0
	}

	arg := core.SafeChild(argList, 3) // 第二个参数
	return d.evaluateSizeExpression(ctx, arg)
}

// evaluateSizeExpression 计算大小表达式的值
func (d *HeapOverflowDetector) evaluateSizeExpression(ctx *core.AnalysisContext, expr *sitter.Node) int64 {
	if expr == nil {
		return 0
	}

	text := ctx.GetSourceText(expr)

	// 常量折叠：如果是数字字面量
	if core.SafeType(expr) == "number_literal" {
		// 去掉后缀（U, L, UL, LL, ULL 等）
		text = strings.TrimSuffix(text, "U")
		text = strings.TrimSuffix(text, "u")
		text = strings.TrimSuffix(text, "L")
		text = strings.TrimSuffix(text, "l")
		text = strings.TrimSuffix(text, "UL")
		text = strings.TrimSuffix(text, "ul")
		text = strings.TrimSuffix(text, "LL")
		text = strings.TrimSuffix(text, "ll")
		text = strings.TrimSuffix(text, "ULL")
		text = strings.TrimSuffix(text, "ull")

		if val, err := strconv.ParseInt(text, 0, 64); err == nil {
			return val
		}
	}

	// sizeof 表达式
	if core.SafeType(expr) == "call_expression" && strings.HasPrefix(text, "sizeof") {
		return d.evaluateSizeof(ctx, expr)
	}

	// 乘法表达式
	if core.SafeType(expr) == "binary_expression" && strings.Contains(text, "*") {
		if core.SafeChildCount(expr) >= 3 {
			left := core.SafeChild(expr, 0)
			right := core.SafeChild(expr, 2)

			// 确认操作符是 *
			op := core.SafeChild(expr, 1)
			if op != nil && ctx.GetSourceText(op) == "*" {
				leftSize := d.evaluateSizeExpression(ctx, left)
				rightSize := d.evaluateSizeExpression(ctx, right)
				return leftSize * rightSize
			}
		}
	}

	// 无法静态确定，返回 0
	return 0
}

// evaluateSizeof 计算 sizeof 表达式的值
func (d *HeapOverflowDetector) evaluateSizeof(ctx *core.AnalysisContext, expr *sitter.Node) int64 {
	if core.SafeChildCount(expr) < 2 {
		return 0
	}

	// sizeof(type) 或 sizeof(expr)
	arg := core.SafeChild(expr, 1)
	text := ctx.GetSourceText(arg)

	// 常见类型的大小
	typeSizes := map[string]int64{
		"char":      1,
		"int":       4,
		"long":      8,
		"long long": 8,
		"short":     2,
		"float":     4,
		"double":    8,
		"void*":     8,
		"char*":     8,
		"int*":      8,
		"size_t":    8,
		"uint8_t":   1,
		"uint16_t":  2,
		"uint32_t":  4,
		"uint64_t":  8,
	}

	// 检查是否是已知类型
	if size, ok := typeSizes[text]; ok {
		return size
	}

	// 如果是 sizeof(variable)，无法静态确定
	return 0
}

// performCrossProceduralAnalysis 执行跨过程分析
func (d *HeapOverflowDetector) performCrossProceduralAnalysis(ctx *core.AnalysisContext) {
	// 查找所有函数调用
	callQuery := `(call_expression) @call`
	callMatches, _ := ctx.Query(callQuery)

	for _, match := range callMatches {
		d.analyzeFunctionCall(ctx, match.Node)
	}
}

// analyzeFunctionCall 分析函数调用，追踪堆对象传递
func (d *HeapOverflowDetector) analyzeFunctionCall(ctx *core.AnalysisContext, callExpr *sitter.Node) {
	// 获取被调用函数名
	calleeName := d.extractCalledFunctionName(ctx, callExpr)
	if calleeName == "" {
		return
	}

	// 获取当前函数（调用者）
	callerFunc := d.findParentFunction(ctx, callExpr)
	if callerFunc == nil {
		return
	}
	callerName := d.extractFunctionName(ctx, callerFunc)

	// 检查传递的参数是否是堆对象
	if core.SafeChildCount(callExpr) < 2 {
		return
	}

	// 遍历参数
	argIndex := 0
	for i := 1; i < int(core.SafeChildCount(callExpr)) && argIndex < 10; i++ {
		arg := core.SafeChild(callExpr, i)

		// 跳过函数名和操作符
		if core.SafeType(arg) == "identifier" || core.SafeType(arg) == "(" || core.SafeType(arg) == "," || core.SafeType(arg) == ")" {
			continue
		}

		// 检查参数是否是堆对象
		argText := ctx.GetSourceText(arg)
		heapObj := d.heapModel.GetObject(callerName, argText)

		if heapObj != nil {
			// 堆对象被传递给被调用函数
			// 记录这个信息：在 callee 函数中，参数 argIndex 是一个堆对象
			d.recordHeapObjectParameter(ctx, calleeName, argIndex, heapObj)
		}

		argIndex++
	}
}

// recordHeapObjectParameter 记录堆对象参数
func (d *HeapOverflowDetector) recordHeapObjectParameter(ctx *core.AnalysisContext, calleeName string, paramIndex int, heapObj *HeapObject) {
	// 在跨过程分析中，我们需要知道某个参数是堆对象
	// 这里简化处理：在函数参数中标记为堆对象
	// 实际实现可能需要更复杂的符号表
}

// DangerousOperation 表示潜在的危险操作
type DangerousOperation struct {
	// 操作类型（strcpy, memcpy, memset, etc.）
	OpType string
	// 操作节点
	Node *sitter.Node
	// 目标缓冲区（可能是堆对象）
	Dest string
	// 源缓冲区/大小
	Source string
	// 大小（如果可确定）
	Size int64
	// 所在函数
	Function string
	// 行号
	Line int
}

// findDangerousOperations 查找所有危险操作
func (d *HeapOverflowDetector) findDangerousOperations(ctx *core.AnalysisContext) []DangerousOperation {
	var ops []DangerousOperation

	// 危险函数集合
	dangerousFuncs := map[string]bool{
		"strcpy": true, "strcat": true, "sprintf": true, "vsprintf": true,
		"memcpy": true, "memmove": true, "memset": true,
		"strncpy": true, "strncat": true,
	}

	// 遍历所有函数定义，查找危险调用
	funcQuery := `(function_definition) @func`
	funcMatches, _ := ctx.Query(funcQuery)

	for _, funcMatch := range funcMatches {
		funcNode := funcMatch.Node
		funcName := d.extractFunctionName(ctx, funcNode)

		// 在函数体中查找所有 call_expression
		d.findCallsInNode(ctx, funcNode, funcName, dangerousFuncs, &ops)
	}

	return ops
}

// findCallsInNode 在节点中递归查找调用表达式
func (d *HeapOverflowDetector) findCallsInNode(ctx *core.AnalysisContext, node *sitter.Node, parentFunc string, dangerousFuncs map[string]bool, ops *[]DangerousOperation) {
	if node == nil {
		return
	}

	// 如果是调用表达式，检查是否是危险函数
	if core.SafeType(node) == "call_expression" {
		calledFuncName := d.extractCalledFunctionName(ctx, node)
		if dangerousFuncs[calledFuncName] {
			if op := d.analyzeDangerousCall(ctx, node, calledFuncName); op != nil {
				op.Function = parentFunc
				*ops = append(*ops, *op)
			}
		}
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		// 跳过参数列表等已处理的节点
		if core.SafeType(child) != "argument_list" {
			d.findCallsInNode(ctx, child, parentFunc, dangerousFuncs, ops)
		}
	}
}

// analyzeDangerousCall 分析危险调用
func (d *HeapOverflowDetector) analyzeDangerousCall(ctx *core.AnalysisContext, callExpr *sitter.Node, funcName string) *DangerousOperation {
	// 首先验证这个调用是否真的是调用指定的危险函数
	calledFuncName := d.extractCalledFunctionName(ctx, callExpr)
	if calledFuncName != funcName {
		return nil
	}

	// 获取所在函数
	parentFunc := d.findParentFunction(ctx, callExpr)
	if parentFunc == nil {
		return nil
	}
	functionName := d.extractFunctionName(ctx, parentFunc)

	line := int(callExpr.StartPoint().Row) + 1

	// 根据不同的函数类型分析参数
	switch funcName {
	case "strcpy", "strcat":
		return d.analyzeStrcpyStrcat(ctx, callExpr, funcName, functionName, line)
	case "memcpy", "memmove", "memset":
		return d.analyzeMemcpyMemset(ctx, callExpr, funcName, functionName, line)
	case "sprintf", "vsprintf":
		return d.analyzeSprintf(ctx, callExpr, funcName, functionName, line)
	case "strncpy", "strncat":
		return d.analyzeStrncpyStrncat(ctx, callExpr, funcName, functionName, line)
	}

	return nil
}

// analyzeStrcpyStrcat 分析 strcpy/strcat 调用
func (d *HeapOverflowDetector) analyzeStrcpyStrcat(ctx *core.AnalysisContext, callExpr *sitter.Node, funcName, callerFunc string, line int) *DangerousOperation {
	if core.SafeChildCount(callExpr) < 2 {
		return nil
	}

	// 获取 argument_list
	argList := core.SafeChild(callExpr, 1)
	if argList == nil || core.SafeType(argList) != "argument_list" {
		return nil
	}

	// argument_list 结构: "(" dest "," src ")"
	// dest 在 child 1, src 在 child 3
	if core.SafeChildCount(argList) < 4 {
		return nil
	}

	dest := core.SafeChild(argList, 1)
	src := core.SafeChild(argList, 3)

	destText := ctx.GetSourceText(dest)
	srcText := ctx.GetSourceText(src)

	return &DangerousOperation{
		OpType:   funcName,
		Node:     callExpr,
		Dest:     destText,
		Source:   srcText,
		Function: callerFunc,
		Line:     line,
	}
}

// analyzeMemcpyMemset 分析 memcpy/memset 调用
func (d *HeapOverflowDetector) analyzeMemcpyMemset(ctx *core.AnalysisContext, callExpr *sitter.Node, funcName, callerFunc string, line int) *DangerousOperation {
	if core.SafeChildCount(callExpr) < 2 {
		return nil
	}

	// 获取 argument_list
	argList := core.SafeChild(callExpr, 1)
	if argList == nil || core.SafeType(argList) != "argument_list" {
		return nil
	}

	// memcpy(dest, src, size) or memset(dest, value, size)
	// 参数在 child 1, 3, 5
	if core.SafeChildCount(argList) < 6 {
		return nil
	}

	dest := core.SafeChild(argList, 1)
	srcOrValue := core.SafeChild(argList, 3)
	size := core.SafeChild(argList, 5)

	destText := ctx.GetSourceText(dest)
	srcText := ctx.GetSourceText(srcOrValue)

	sizeValue := d.evaluateSizeExpression(ctx, size)

	return &DangerousOperation{
		OpType:   funcName,
		Node:     callExpr,
		Dest:     destText,
		Source:   srcText,
		Size:     sizeValue,
		Function: callerFunc,
		Line:     line,
	}
}

// analyzeSprintf 分析 sprintf 调用
func (d *HeapOverflowDetector) analyzeSprintf(ctx *core.AnalysisContext, callExpr *sitter.Node, funcName, callerFunc string, line int) *DangerousOperation {
	if core.SafeChildCount(callExpr) < 2 {
		return nil
	}

	// 获取 argument_list
	argList := core.SafeChild(callExpr, 1)
	if argList == nil || core.SafeType(argList) != "argument_list" {
		return nil
	}

	// sprintf(dest, format, ...)
	// dest 在 child 1, format 在 child 3
	if core.SafeChildCount(argList) < 4 {
		return nil
	}

	dest := core.SafeChild(argList, 1)
	format := core.SafeChild(argList, 3)

	destText := ctx.GetSourceText(dest)
	formatText := ctx.GetSourceText(format)

	return &DangerousOperation{
		OpType:   funcName,
		Node:     callExpr,
		Dest:     destText,
		Source:   formatText,
		Function: callerFunc,
		Line:     line,
	}
}

// analyzeStrncpyStrncat 分析 strncpy/strncat 调用
func (d *HeapOverflowDetector) analyzeStrncpyStrncat(ctx *core.AnalysisContext, callExpr *sitter.Node, funcName, callerFunc string, line int) *DangerousOperation {
	if core.SafeChildCount(callExpr) < 2 {
		return nil
	}

	// 获取 argument_list
	argList := core.SafeChild(callExpr, 1)
	if argList == nil || core.SafeType(argList) != "argument_list" {
		return nil
	}

	// strncpy(dest, src, size) or strncat(dest, src, size)
	// 参数在 child 1, 3, 5
	if core.SafeChildCount(argList) < 6 {
		return nil
	}

	dest := core.SafeChild(argList, 1)
	src := core.SafeChild(argList, 3)
	size := core.SafeChild(argList, 5)

	destText := ctx.GetSourceText(dest)
	srcText := ctx.GetSourceText(src)

	sizeValue := d.evaluateSizeExpression(ctx, size)

	return &DangerousOperation{
		OpType:   funcName,
		Node:     callExpr,
		Dest:     destText,
		Source:   srcText,
		Size:     sizeValue,
		Function: callerFunc,
		Line:     line,
	}
}

// analyzeDangerousOperation 分析危险操作
func (d *HeapOverflowDetector) analyzeDangerousOperation(ctx *core.AnalysisContext, op DangerousOperation) *core.DetectorVulnerability {
	// 检查目标缓冲区是否是堆对象
	heapObj := d.heapModel.GetObjectInAnyScope(op.Dest, op.Function)

	if heapObj == nil {
		// 不是堆对象，不报告（由其他检测器处理）
		return nil
	}

	// 优先检查：如果堆对象的大小被污染，直接报告高危漏洞
	if heapObj.IsTainted {
		message := fmt.Sprintf("Heap buffer overflow with user-controlled size: %s() on heap object '%s' at line %d. Heap object allocated at line %d with tainted size expression '%s'. This allows an attacker to control the allocation size and cause overflow.",
			op.OpType, op.Dest, op.Line, heapObj.Line, heapObj.SizeExpr)

		// 如果有污点路径，添加到消息中
		if len(heapObj.TaintPath) > 0 {
			message += fmt.Sprintf(" Taint path: %v", heapObj.TaintPath)
		}

		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE122,
			message,
			op.Node,
			core.ConfidenceHigh,
			core.SeverityCritical,
		)
		return &vuln
	}

	// 计算需要的缓冲区大小
	requiredSize := d.calculateRequiredSize(ctx, op)

	// 使用 Z3 检查是否会溢出（考虑复杂表达式和约束）
	if d.checkConstraintsWithZ3(ctx, heapObj, requiredSize) {
		var message string

		// 根据堆对象类型生成不同的消息
		if heapObj.IsSizeExpr && heapObj.Size == 0 {
			message = fmt.Sprintf("Heap buffer overflow with complex size: %s() on heap object '%s' at line %d. Heap object allocated at line %d with complex size expression '%s'. Z3 analysis indicates potential overflow.",
				op.OpType, op.Dest, op.Line, heapObj.Line, heapObj.SizeExpr)
		} else {
			message = fmt.Sprintf("Heap buffer overflow: %s() writes %d bytes to heap object '%s' (allocated at line %d, size: %d bytes) at line %d",
				op.OpType, requiredSize, op.Dest, heapObj.Line, heapObj.Size, op.Line)
		}

		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE122,
			message,
			op.Node,
			core.ConfidenceHigh,
			core.SeverityCritical,
		)
		return &vuln
	}

	// 即使大小匹配，也可能有风险（如 strcpy 不检查终止符）
	if d.isRiskyOperation(op) {
		message := fmt.Sprintf("Potential heap buffer overflow: %s() to heap object '%s' (size: %d bytes) at line %d. No bounds checking - source may be larger than destination",
			op.OpType, op.Dest, heapObj.Size, op.Line)

		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE122,
			message,
			op.Node,
			core.ConfidenceMedium,
			core.SeverityHigh,
		)
		return &vuln
	}

	return nil
}

// calculateRequiredSize 计算所需缓冲区大小
func (d *HeapOverflowDetector) calculateRequiredSize(ctx *core.AnalysisContext, op DangerousOperation) int64 {
	switch op.OpType {
	case "memcpy", "memmove", "memset":
		return op.Size
	case "strcpy":
		// strcpy 大小未知，假设最大风险
		return -1 // 表示大小未知
	case "strncpy":
		return op.Size
	case "sprintf", "vsprintf":
		// sprintf 大小未知，假设最大风险
		return -1
	case "strncat":
		return op.Size
	default:
		return -1
	}
}

// isRiskyOperation 检查是否是风险操作（无边界检查）
func (d *HeapOverflowDetector) isRiskyOperation(op DangerousOperation) bool {
	riskyOps := []string{"strcpy", "strcat", "sprintf", "vsprintf"}

	for _, risky := range riskyOps {
		if op.OpType == risky {
			return true
		}
	}

	return false
}

// analyzeExpressionWithZ3 使用 Z3 分析复杂表达式是否可能溢出
// 返回：是否可能溢出、表达式的最小值、最大值
func (d *HeapOverflowDetector) analyzeExpressionWithZ3(ctx *core.AnalysisContext, expr *sitter.Node) (bool, int64, int64) {
	if d.z3Solver == nil || !d.z3Solver.IsAvailable() {
		// Z3 不可用，使用保守估计
		return false, 0, 0
	}

	exprText := ctx.GetSourceText(expr)

	// 简单情况：常量表达式
	if core.SafeType(expr) == "number_literal" {
		size := d.evaluateSizeExpression(ctx, expr)
		return false, size, size
	}

	// 复杂表达式：使用 Z3 进行符号执行
	// 对于 malloc(n * m) 这样的表达式，检查是否可能溢出

	// 检查是否是乘法表达式
	if core.SafeType(expr) == "binary_expression" && strings.Contains(exprText, "*") {
		if core.SafeChildCount(expr) >= 3 {
			left := core.SafeChild(expr, 0)
			right := core.SafeChild(expr, 2)
			op := core.SafeChild(expr, 1)

			if op != nil && ctx.GetSourceText(op) == "*" {
				// 检查乘法是否可能溢出
				if d.z3Solver.CheckOverflow(left, right) {
					return true, 0, -1 // 可能溢出
				}
			}
		}
	}

	// 检查是否是 sizeof 表达式
	if strings.HasPrefix(exprText, "sizeof") {
		size := d.evaluateSizeExpression(ctx, expr)
		return false, size, size
	}

	// 其他复杂表达式：保守处理
	return false, 0, 0
}

// checkConstraintsWithZ3 使用 Z3 检查约束条件下的溢出可能性
func (d *HeapOverflowDetector) checkConstraintsWithZ3(ctx *core.AnalysisContext, heapObj *HeapObject, requiredSize int64) bool {
	if d.z3Solver == nil || !d.z3Solver.IsAvailable() {
		// Z3 不可用，使用简单检查
		return requiredSize > heapObj.Size
	}

	// 如果大小是污点的，假设可能溢出
	if heapObj.IsTainted {
		return true
	}

	// 如果大小是表达式，使用 Z3 分析
	if heapObj.IsSizeExpr && heapObj.Size == 0 {
		mayOverflow, _, maxSize := d.analyzeExpressionWithZ3(ctx, heapObj.AllocNode)

		if mayOverflow {
			return true
		}

		// 如果能确定大小范围，检查是否可能溢出
		if maxSize > 0 && requiredSize > maxSize {
			return true
		}
	}

	// 默认检查
	return requiredSize > heapObj.Size
}

// Helper functions

// extractFunctionName 提取函数名
func (d *HeapOverflowDetector) extractFunctionName(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
	// 处理不同的函数声明格式
	for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
		child := core.SafeChild(funcNode, i)

		// 情况1: function_declarator
		if core.SafeType(child) == "function_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "identifier" {
					return ctx.GetSourceText(subChild)
				}
			}
		}

		// 情况2: pointer_declarator（返回指针的函数）
		if core.SafeType(child) == "pointer_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "function_declarator" {
					for k := 0; k < int(core.SafeChildCount(subChild)); k++ {
						subSubChild := core.SafeChild(subChild, k)
						if core.SafeType(subSubChild) == "identifier" {
							return ctx.GetSourceText(subSubChild)
						}
					}
				}
				if core.SafeType(subChild) == "identifier" {
					// 检查后面是否是参数列表
					if j+1 < int(core.SafeChildCount(child)) {
						nextChild := core.SafeChild(child, j+1)
						if core.SafeType(nextChild) == "parameter_list" {
							return ctx.GetSourceText(subChild)
						}
					}
				}
			}
		}
	}
	return ""
}

// extractCalledFunctionName 提取被调用函数名
func (d *HeapOverflowDetector) extractCalledFunctionName(ctx *core.AnalysisContext, callExpr *sitter.Node) string {
	if core.SafeChildCount(callExpr) < 1 {
		return ""
	}

	function := core.SafeChild(callExpr, 0)
	funcText := ctx.GetSourceText(function)

	// 去掉可能的命名空间前缀
	if idx := strings.LastIndex(funcText, "::"); idx != -1 {
		funcText = funcText[idx+2:]
	}

	return funcText
}

// isAnyNodeTainted 递归检查节点或其任何子节点是否被污染
func (d *HeapOverflowDetector) isAnyNodeTainted(node *sitter.Node) bool {
	if d.taintEngine == nil || node == nil {
		return false
	}

	// 检查当前节点
	if d.taintEngine.IsTainted(node) {
		return true
	}

	// 递归检查所有子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if d.isAnyNodeTainted(child) {
			return true
		}
	}

	return false
}

// isIdentifierTainted 检查标识符是否被污染（通过查找其定义）
// 这是处理间接污点传播的关键方法，例如：
//
//	size_t user_size;
//	scanf("%zu", &user_size);  // 污点源
//	size_t actual_size = user_size * 2;  // 污点传播
//	malloc(actual_size)  // actual_size 是标识符，需要查找其定义
func (d *HeapOverflowDetector) isIdentifierTainted(ctx *core.AnalysisContext, identifier *sitter.Node, funcNode *sitter.Node) bool {
	if d.taintEngine == nil || identifier == nil || core.SafeType(identifier) != "identifier" {
		return false
	}

	varName := ctx.GetSourceText(identifier)

	// 1. 首先检查变量名是否在污点变量集合中
	if d.taintEngine.IsTainted(identifier) {
		return true
	}

	// 2. 在当前函数中查找该变量的声明
	// 搜索所有声明节点，查找匹配的变量名
	declQuery := `(declaration) @decl`
	declMatches, _ := ctx.Query(declQuery)

	for _, match := range declMatches {
		// 检查是否在当前函数作用域内
		if !d.isNodeInFunction(match.Node, funcNode) {
			continue
		}

		// 在声明中查找变量声明符
		varDecl := d.findVariableDeclaration(match.Node, varName, ctx)
		if varDecl != nil {

			// 递归检查声明节点的所有子节点是否被污染
			// 这处理了污点传播标记子节点的情况
			if d.isAnyNodeTainted(varDecl) {
				return true
			}

			// 如果有初始化表达式，检查初始化表达式是否被污染
			initExpr := d.findInitDeclaratorValue(varDecl)
			if initExpr != nil {

				// 检查初始化表达式本身
				if d.taintEngine.IsTainted(initExpr) {
					return true
				}

				// 如果是赋值表达式，检查右值是否被污染
				// 例如: size_t actual_size = user_size * 2;
				// 这里的 initExpr 是赋值表达式 "=" 或其子表达式
				if core.SafeType(initExpr) == "binary_expression" {
					// 检查操作数是否被污染
					left := core.SafeChild(initExpr, 0)
					right := core.SafeChild(initExpr, 2)
					if left != nil && d.taintEngine.IsTainted(left) {
						return true
					}
					if right != nil && d.taintEngine.IsTainted(right) {
						return true
					}
				}

				// 递归检查初始化表达式的子树
				if d.isAnyNodeTainted(initExpr) {
					return true
				}
			}
		}
	}

	// 3. 查找赋值表达式（可能在声明之后重新赋值）
	assignQuery := `(assignment_expression) @assign`
	assignMatches, _ := ctx.Query(assignQuery)

	for _, match := range assignMatches {
		if !d.isNodeInFunction(match.Node, funcNode) {
			continue
		}

		left := match.Node.Child(0)
		if left != nil && core.SafeType(left) == "identifier" && ctx.GetSourceText(left) == varName {
			right := match.Node.Child(2)
			if right != nil && d.taintEngine.IsTainted(right) {
				return true
			}
		}
	}

	return false
}

// isNodeInFunction 检查节点是否在函数内
func (d *HeapOverflowDetector) isNodeInFunction(node, funcNode *sitter.Node) bool {
	if node == nil || funcNode == nil {
		return false
	}

	// 检查节点的位置是否在函数的范围内
	nodeStart := node.StartByte()
	nodeEnd := node.EndByte()
	funcStart := funcNode.StartByte()
	funcEnd := funcNode.EndByte()

	return nodeStart >= funcStart && nodeEnd <= funcEnd
}

// findVariableDeclaration 在声明节点中查找指定名称的变量声明
func (d *HeapOverflowDetector) findVariableDeclaration(declNode *sitter.Node, varName string, ctx *core.AnalysisContext) *sitter.Node {
	if declNode == nil {
		return nil
	}

	// 调试：打印声明节点的信息
	declText := ctx.GetSourceText(declNode)
	if len(declText) > 50 {
		declText = declText[:50] + "..."
	}

	// 遍历声明节点的子节点
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)

		// 检查 init_declarator
		if core.SafeType(child) == "init_declarator" {
			declarator := d.findDeclaratorInInitDeclarator(child)
			if declarator != nil {
				// 检查标识符名称
				identifier := d.extractIdentifierFromDeclarator(declarator)
				if identifier != nil && core.SafeType(identifier) == "identifier" {
					// 比较变量名
					identifierName := ctx.GetSourceText(identifier)
					if identifierName == varName {
						return child
					}
				}
			}
		}
	}

	return nil
}

// findDeclaratorInInitDeclarator 从 init_declarator 中提取 declarator
func (d *HeapOverflowDetector) findDeclaratorInInitDeclarator(initDecl *sitter.Node) *sitter.Node {
	if initDecl == nil {
		return nil
	}

	for i := 0; i < int(core.SafeChildCount(initDecl)); i++ {
		child := core.SafeChild(initDecl, i)
		// declarator 可能是 pointer_declarator, array_declarator, function_declarator 等
		// 也可能直接就是 identifier（例如：size_t actual_size = ...）
		if strings.HasSuffix(core.SafeType(child), "_declarator") || core.SafeType(child) == "identifier" {
			return child
		}
		// 递归查找
		if found := d.findDeclaratorInInitDeclarator(child); found != nil {
			return found
		}
	}

	return nil
}

// extractIdentifierFromDeclarator 从声明符中提取标识符
func (d *HeapOverflowDetector) extractIdentifierFromDeclarator(declarator *sitter.Node) *sitter.Node {
	if declarator == nil {
		return nil
	}

	// 如果当前节点就是标识符
	if core.SafeType(declarator) == "identifier" {
		return declarator
	}

	// 递归查找子节点中的标识符
	for i := 0; i < int(core.SafeChildCount(declarator)); i++ {
		child := core.SafeChild(declarator, i)
		if core.SafeType(child) == "identifier" {
			return child
		}
		// 递归查找（处理 pointer_declarator 等嵌套情况）
		if found := d.extractIdentifierFromDeclarator(child); found != nil {
			return found
		}
	}

	return nil
}

// findParentFunction 查找包含节点的函数
func (d *HeapOverflowDetector) findParentFunction(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
	parent := node.Parent()
	depth := 0
	maxDepth := 30

	for parent != nil && depth < maxDepth {
		if core.SafeType(parent) == "function_definition" {
			return parent
		}
		parent = parent.Parent()
		depth++
	}

	return nil
}

// extractDeclaratorName 提取声明符中的变量名
func (d *HeapOverflowDetector) extractDeclaratorName(ctx *core.AnalysisContext, initDecl *sitter.Node) string {
	for i := 0; i < int(core.SafeChildCount(initDecl)); i++ {
		child := core.SafeChild(initDecl, i)
		if core.SafeType(child) == "pointer_declarator" || core.SafeType(child) == "array_declarator" {
			return d.extractIdentifierNameFromDeclarator(ctx, child)
		}
		if core.SafeType(child) == "identifier" {
			return ctx.GetSourceText(child)
		}
	}
	return ""
}

// extractIdentifierNameFromDeclarator 从声明符中提取标识符名称（返回字符串）
func (d *HeapOverflowDetector) extractIdentifierNameFromDeclarator(ctx *core.AnalysisContext, declarator *sitter.Node) string {
	for i := 0; i < int(core.SafeChildCount(declarator)); i++ {
		child := core.SafeChild(declarator, i)
		if core.SafeType(child) == "identifier" {
			return ctx.GetSourceText(child)
		}
		if core.SafeType(child) == "pointer_declarator" || core.SafeType(child) == "array_declarator" {
			return d.extractIdentifierNameFromDeclarator(ctx, child)
		}
	}
	return ""
}

// findInitDeclaratorValue 查找初始化声明符的值
func (d *HeapOverflowDetector) findInitDeclaratorValue(initDecl *sitter.Node) *sitter.Node {
	for i := 0; i < int(core.SafeChildCount(initDecl)); i++ {
		child := core.SafeChild(initDecl, i)
		if core.SafeType(child) == "=" || core.SafeType(child) == "call_expression" {
			if core.SafeType(child) == "=" && i+1 < int(core.SafeChildCount(initDecl)) {
				return core.SafeChild(initDecl, i+1)
			}
			if core.SafeType(child) == "call_expression" {
				return child
			}
		}
	}
	return nil
}
