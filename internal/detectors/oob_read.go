package detectors

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// OOBReadDetector 越界读取检测器
type OOBReadDetector struct {
	*core.BaseDetector
	// 数组模型
	arrayModel *ArrayModel
	// 污点分析引擎
	taintEngine *core.MemoryTaintEngine
	// 分析上下文
	analysisCtx *core.AnalysisContext
	// Z3 约束求解器
	z3Solver core.Z3Solver
	// 跨函数调用图（用于追踪常量参数值）
	callGraph *CallGraph
}

// ArrayInfo 表示一个数组的信息
type ArrayInfo struct {
	// 数组名
	Name string
	// 数组大小（元素数量）
	Size int64
	// 元素大小（字节）
	ElementSize int64
	// 数组类型（固定数组、VLA、指针）
	ArrayType string
	// 分配节点
	DeclNode *sitter.Node
	// 所在函数
	Function string
	// 所在行号
	Line int
	// 是否是全局数组
	IsGlobal bool
	// 维度信息（多维数组）
	Dimensions []int64
	// 是否是大小受污点污染
	IsTainted bool
	// 大小表达式（用于 VLA）
	SizeExpr string
}

// ArrayModel 数组模型
type ArrayModel struct {
	// 数组信息映射
	// key: functionName:arrayName
	arrays map[string]*ArrayInfo
	mu     sync.RWMutex // 保护map的并发访问
}

// CallInfo 存储函数调用信息
type CallInfo struct {
	FunctionName string  // 被调用的函数名
	ArgValues    []int64 // 参数值列表（仅常量参数，-1表示非常量）
	CallerFunc   string  // 调用者函数名
	LineNumber   int     // 调用所在行号
}

// CallGraph 存储跨函数调用信息
type CallGraph struct {
	calls map[string][]*CallInfo // key: functionName, value: 调用该函数的信息列表
	mu    sync.RWMutex
}

// NewOOBReadDetector 创建越界读取检测器
func NewOOBReadDetector() *OOBReadDetector {
	return &OOBReadDetector{
		BaseDetector: core.NewBaseDetector("Out-of-Bounds Read Detector", "Detects out-of-bounds read vulnerabilities using taint analysis and array bounds checking"),
		arrayModel:   NewArrayModel(),
		taintEngine:  nil,
		z3Solver:     nil,
		callGraph:    NewCallGraph(),
	}
}

// NewCallGraph 创建调用图
func NewCallGraph() *CallGraph {
	return &CallGraph{
		calls: make(map[string][]*CallInfo),
	}
}

// NewArrayModel 创建数组模型
func NewArrayModel() *ArrayModel {
	return &ArrayModel{
		arrays: make(map[string]*ArrayInfo),
	}
}

// AddArray 添加数组信息（并发安全）
func (m *ArrayModel) AddArray(funcName, arrayName string, info *ArrayInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	info.Name = arrayName
	info.Function = funcName
	key := funcName + ":" + arrayName
	m.arrays[key] = info
}

// GetArray 获取数组信息（并发安全）
func (m *ArrayModel) GetArray(funcName, arrayName string) *ArrayInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := funcName + ":" + arrayName
	return m.arrays[key]
}

// GetArrayInAnyScope 在任何作用域查找数组（并发安全）
func (m *ArrayModel) GetArrayInAnyScope(arrayName string, currentFunc string) *ArrayInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 优先查找当前函数
	key := currentFunc + ":" + arrayName
	if arr, ok := m.arrays[key]; ok {
		return arr
	}

	// 查找全局数组（函数名为空）
	key = ":" + arrayName
	if arr, ok := m.arrays[key]; ok {
		return arr
	}

	// 查找其他函数中的数组（用于跨函数分析）
	for key, arr := range m.arrays {
		if strings.HasSuffix(key, ":"+arrayName) {
			return arr
		}
	}
	return nil
}

// Run 运行检测器
func (d *OOBReadDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 保存分析上下文
	d.analysisCtx = ctx

	// 【新增】跳过头文件（头文件通常包含宏定义和接口声明，不是实际执行代码）
	if d.isHeaderFile(ctx.Unit.FilePath) {
		return vulns, nil
	}

	// 初始化 Z3 求解器
	if d.z3Solver == nil {
		if solver, err := core.CreateZ3Solver(); err == nil {
			d.z3Solver = solver
			defer d.z3Solver.Close()
		}
	}

	// 初始化污点分析引擎
	if d.taintEngine == nil {
		d.taintEngine = core.NewMemoryTaintEngine(ctx)
	}

	// 执行污点传播分析
	if ctx.CFG != nil && ctx.CFG.Entry != nil {
		if err := d.taintEngine.Propagate(ctx.CFG); err != nil {
		}
	}

	// 1. 收集所有数组信息
	d.collectArrays(ctx)

	// 1.5. 【新增】收集跨函数调用信息（用于常量参数值追踪）
	d.collectCallGraph(ctx)

	// 2. 检测数组访问表达式
	accessExprs := d.findArrayAccessExpressions(ctx)

	// 3. 分析每个访问表达式
	for _, access := range accessExprs {
		if vuln := d.analyzeArrayAccess(ctx, access); vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	// 4. 检测指针解引用访问
	ptrAccessExprs := d.findPointerAccessExpressions(ctx)

	for _, access := range ptrAccessExprs {
		if vuln := d.analyzePointerAccess(ctx, access); vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	return vulns, nil
}

// ArrayAccessExpression 数组访问表达式
type ArrayAccessExpression struct {
	// 数组名
	ArrayName string
	// 索引表达式节点
	IndexNode *sitter.Node
	// 索引表达式文本
	IndexExpr string
	// 访问节点
	AccessNode *sitter.Node
	// 所在函数
	Function string
	// 所在行号
	Line int
	// 访问类型（read/write）
	AccessType string
	// 是否是读取访问
	IsRead bool
	// 数组维度（对于多维数组）
	Dimensions int
	// 嵌套的索引（多维数组）
	NestedIndices []*sitter.Node
	// 优化3: 添加置信度评估所需的字段
	IndexIsConstant bool  // 索引是否是常量
	IndexValue      int64 // 索引常量值
	IndexIsTainted  bool  // 索引是否被污染
}

// collectArrays 收集所有数组信息
func (d *OOBReadDetector) collectArrays(ctx *core.AnalysisContext) {
	// 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, _ := ctx.Query(funcQuery)

	// 首先收集全局数组（函数外的声明）
	d.collectArraysInScope(ctx, nil, "")

	// 然后收集每个函数中的数组
	for _, funcMatch := range funcMatches {
		funcName := d.extractFunctionName(ctx, funcMatch.Node)
		if funcName == "" {
			continue
		}
		// 优化1: 检查函数是否在预处理注释块中
		if d.isNodeInPreprocessorComment(ctx, funcMatch.Node) {
			continue
		}
		d.collectArraysInFunction(ctx, funcMatch.Node, funcName)
	}
}

// collectCallGraph 收集跨函数调用信息（用于常量参数值追踪）
func (d *OOBReadDetector) collectCallGraph(ctx *core.AnalysisContext) {
	// 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, _ := ctx.Query(funcQuery)

	// 为每个函数收集调用信息
	for _, funcMatch := range funcMatches {
		funcName := d.extractFunctionName(ctx, funcMatch.Node)
		if funcName == "" {
			continue
		}

		// 查找函数体
		var funcBody *sitter.Node
		for i := 0; i < int(core.SafeChildCount(funcMatch.Node)); i++ {
			child := core.SafeChild(funcMatch.Node, i)
			if core.SafeType(child) == "compound_statement" {
				funcBody = child
				break
			}
		}

		if funcBody == nil {
			continue
		}

		// 在函数体内查找所有 call_expression
		callQuery := `(call_expression) @call`
		callMatches, _ := ctx.Query(callQuery)

		for _, callMatch := range callMatches {
			// 检查调用是否在当前函数体内
			if !d.isNodeInScope(callMatch.Node, funcBody) {
				continue
			}

			// 提取被调用函数名
			calledFuncName := d.extractCalledFunctionName(ctx, callMatch.Node)
			if calledFuncName == "" {
				continue
			}

			// 提取参数值（仅常量）
			argValues := d.extractCallArgValues(ctx, callMatch.Node)

			// 记录调用信息
			line := int(callMatch.Node.StartPoint().Row) + 1
			callInfo := &CallInfo{
				FunctionName: calledFuncName,
				ArgValues:    argValues,
				CallerFunc:   funcName,
				LineNumber:   line,
			}

			d.callGraph.AddCall(calledFuncName, callInfo)
		}
	}
}

// extractCalledFunctionName 提取被调用函数名
func (d *OOBReadDetector) extractCalledFunctionName(ctx *core.AnalysisContext, callNode *sitter.Node) string {
	// call_expression 的第一个子节点是函数
	funcNode := core.SafeChild(callNode, 0)
	if funcNode == nil {
		return ""
	}

	funcType := core.SafeType(funcNode)
	// 处理 identifier: func_name
	if funcType == "identifier" {
		return ctx.GetSourceText(funcNode)
	}
	// 处理 field_expression: obj.func_name
	if funcType == "field_expression" {
		fieldNode := core.SafeChild(funcNode, 2) // field: 递归第三个子节点
		if fieldNode != nil && core.SafeType(fieldNode) == "identifier" {
			return ctx.GetSourceText(fieldNode)
		}
	}

	return ""
}

// extractCallArgValues 提取调用参数值（仅常量）
func (d *OOBReadDetector) extractCallArgValues(ctx *core.AnalysisContext, callNode *sitter.Node) []int64 {
	// call_expression 结构: func(arg1, arg2, ...)
	// arguments 是第二个子节点（索引1）
	argsNode := core.SafeChild(callNode, 1)
	if argsNode == nil || core.SafeType(argsNode) != "argument_list" {
		return nil
	}

	var argValues []int64
	for i := 0; i < int(core.SafeChildCount(argsNode)); i++ {
		argNode := core.SafeChild(argsNode, i)
		if argNode == nil {
			continue
		}

		argType := core.SafeType(argNode)
		// 跳过逗号分隔符和括号
		if argType == "," || argType == "(" || argType == ")" {
			continue
		}

		// 尝试计算参数值
		val := d.evaluateIndexExpression(ctx, argNode)
		argValues = append(argValues, val)
	}

	return argValues
}

// AddCall 添加调用信息
func (cg *CallGraph) AddCall(funcName string, callInfo *CallInfo) {
	cg.mu.Lock()
	defer cg.mu.Unlock()

	if cg.calls == nil {
		cg.calls = make(map[string][]*CallInfo)
	}

	cg.calls[funcName] = append(cg.calls[funcName], callInfo)
}

// GetPossibleArgValues 获取函数参数的可能值（来自调用点）
func (cg *CallGraph) GetPossibleArgValues(funcName string, paramIndex int) []int64 {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	calls := cg.calls[funcName]
	if len(calls) == 0 {
		return nil
	}

	var values []int64
	seen := make(map[int64]bool)

	for _, call := range calls {
		if paramIndex < len(call.ArgValues) {
			val := call.ArgValues[paramIndex]
			// 只返回有效的常量值（>= 0）
			if val >= 0 && !seen[val] {
				values = append(values, val)
				seen[val] = true
			}
		}
	}

	return values
}

// collectArraysInFunction 在函数中收集数组
func (d *OOBReadDetector) collectArraysInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, funcName string) {
	// 查找函数体
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

	d.collectArraysInScope(ctx, funcBody, funcName)
}

// collectArraysInScope 在作用域中收集数组
func (d *OOBReadDetector) collectArraysInScope(ctx *core.AnalysisContext, scopeNode *sitter.Node, funcName string) {
	// 查找所有声明
	declQuery := `(declaration) @decl`
	declMatches, _ := ctx.Query(declQuery)

	var filteredDecls []*sitter.Node
	if scopeNode != nil {
		// 过滤出在当前作用域内的声明
		for _, match := range declMatches {
			if d.isNodeInScope(match.Node, scopeNode) {
				filteredDecls = append(filteredDecls, match.Node)
			}
		}
	} else {
		// 全局作用域，使用所有声明
		for _, match := range declMatches {
			filteredDecls = append(filteredDecls, match.Node)
		}
	}

	for _, declNode := range filteredDecls {
		d.extractArrayFromDeclaration(ctx, declNode, funcName)
	}
}

// isNodeInScope 检查节点是否在作用域内
func (d *OOBReadDetector) isNodeInScope(node, scopeNode *sitter.Node) bool {
	if node == nil || scopeNode == nil {
		return false
	}

	nodeStart := node.StartByte()
	nodeEnd := node.EndByte()
	scopeStart := scopeNode.StartByte()
	scopeEnd := scopeNode.EndByte()

	return nodeStart >= scopeStart && nodeEnd <= scopeEnd
}

// extractArrayFromDeclaration 从声明中提取数组信息
func (d *OOBReadDetector) extractArrayFromDeclaration(ctx *core.AnalysisContext, declNode *sitter.Node, funcName string) {
	// 首先查找 init_declarator
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)

		// 检查 init_declarator
		if core.SafeType(child) == "init_declarator" {
			d.extractArrayFromInitDeclarator(ctx, child, funcName)
			return
		}

		// 检查其他类型的声明符（没有初始化的声明）
		if strings.HasSuffix(core.SafeType(child), "_declarator") {
			d.extractArrayFromDeclarator(ctx, child, funcName)
			return
		}
	}

	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
	}
}

// extractArrayFromDeclarator 直接从声明符中提取数组
func (d *OOBReadDetector) extractArrayFromDeclarator(ctx *core.AnalysisContext, declarator *sitter.Node, funcName string) {

	// 检查是否是数组类型
	arrayType := d.getArrayType(declarator)
	if arrayType == "" {
		return
	}

	// 提取数组名
	arrayName := d.extractArrayNameFromDeclarator(ctx, declarator)
	if arrayName == "" {
		return
	}

	line := int(declarator.StartPoint().Row) + 1

	// 分析数组大小和维度
	size, elemSize, dimensions, sizeExpr := d.analyzeArraySize(ctx, declarator, funcName)

	// 检查大小是否被污染
	isTainted := false
	if sizeExpr != "" && d.taintEngine != nil {
		// 对于 VLA (variable-length array)，检查大小表达式是否被污染
		if d.taintEngine.IsTainted(declarator) {
			isTainted = true
		}
	}

	arrayInfo := &ArrayInfo{
		Name:        arrayName,
		Size:        size,
		ElementSize: elemSize,
		ArrayType:   arrayType,
		DeclNode:    declarator,
		Function:    funcName,
		Line:        line,
		IsGlobal:    funcName == "",
		Dimensions:  dimensions,
		IsTainted:   isTainted,
		SizeExpr:    sizeExpr,
	}

	d.arrayModel.AddArray(funcName, arrayName, arrayInfo)
}

// extractArrayFromInitDeclarator 从初始化声明符中提取数组
func (d *OOBReadDetector) extractArrayFromInitDeclarator(ctx *core.AnalysisContext, initDecl *sitter.Node, funcName string) {
	// 提取声明符
	declarator := d.findDeclarator(initDecl)
	if declarator == nil {
		return
	}

	// 检查是否是数组类型
	arrayType := d.getArrayType(declarator)
	if arrayType == "" {
		return
	}

	// 提取数组名
	arrayName := d.extractArrayNameFromDeclarator(ctx, declarator)
	if arrayName == "" {
		return
	}

	line := int(initDecl.StartPoint().Row) + 1

	// 分析数组大小和维度
	size, elemSize, dimensions, sizeExpr := d.analyzeArraySize(ctx, declarator, funcName)

	// 检查大小是否被污染
	isTainted := false
	if sizeExpr != "" && d.taintEngine != nil {
		// 对于 VLA (variable-length array)，检查大小表达式是否被污染
		initValue := d.findInitDeclaratorValue(initDecl)
		if initValue != nil && d.taintEngine.IsTainted(initValue) {
			isTainted = true
		}
	}

	arrayInfo := &ArrayInfo{
		Name:        arrayName,
		Size:        size,
		ElementSize: elemSize,
		ArrayType:   arrayType,
		DeclNode:    initDecl,
		Function:    funcName,
		Line:        line,
		IsGlobal:    funcName == "",
		Dimensions:  dimensions,
		IsTainted:   isTainted,
		SizeExpr:    sizeExpr,
	}

	d.arrayModel.AddArray(funcName, arrayName, arrayInfo)
}

// findDeclarator 查找声明符
func (d *OOBReadDetector) findDeclarator(initDecl *sitter.Node) *sitter.Node {
	if initDecl == nil {
		return nil
	}

	for i := 0; i < int(core.SafeChildCount(initDecl)); i++ {
		child := core.SafeChild(initDecl, i)
		if strings.HasSuffix(core.SafeType(child), "_declarator") {
			return child
		}
	}

	return nil
}

// getArrayType 获取数组类型
func (d *OOBReadDetector) getArrayType(declarator *sitter.Node) string {
	if declarator == nil {
		return ""
	}

	// array_declarator: 固定数组
	if core.SafeType(declarator) == "array_declarator" {
		return "fixed_array"
	}

	// pointer_declarator: 可能是指针或动态数组
	if core.SafeType(declarator) == "pointer_declarator" {
		return "pointer"
	}

	return ""
}

// analyzeArraySize 分析数组大小
func (d *OOBReadDetector) analyzeArraySize(ctx *core.AnalysisContext, declarator *sitter.Node, funcName string) (size, elemSize int64, dimensions []int64, sizeExpr string) {
	dimensions = []int64{}

	// 递归分析数组维度
	currentDeclarator := declarator
	for currentDeclarator != nil {
		if core.SafeType(currentDeclarator) == "array_declarator" {
			// 获取数组大小
			for i := 0; i < int(core.SafeChildCount(currentDeclarator)); i++ {
				child := core.SafeChild(currentDeclarator, i)

				if core.SafeType(child) == "number_literal" {
					// 固定大小数组
					dim := d.evaluateNumberLiteral(ctx, child)
					dimensions = append(dimensions, dim)

					// 计算总大小
					if len(dimensions) == 1 {
						size = dim
					} else {
						size = 1
						for _, d := range dimensions {
							size *= d
						}
					}
				}
			}

			// 移动到内部声明符
			nextDeclarator := (*sitter.Node)(nil)
			for i := 0; i < int(core.SafeChildCount(currentDeclarator)); i++ {
				child := core.SafeChild(currentDeclarator, i)
				if core.SafeType(child) == "array_declarator" {
					nextDeclarator = child
					break
				}
			}
			currentDeclarator = nextDeclarator
		} else {
			break
		}
	}

	// 如果没有找到维度信息，可能是指针
	if len(dimensions) == 0 {
		// 尝试从类型信息推断
		typeNode := core.SafeChild(declarator, 0) // 第一个子节点通常是类型
		if typeNode != nil {
			typeText := ctx.GetSourceText(typeNode)
			elemSize = d.getTypeSize(typeText)
		}
	} else {
		// 计算元素大小
		typeNode := core.SafeChild(declarator, 0)
		if typeNode != nil {
			typeText := ctx.GetSourceText(typeNode)
			elemSize = d.getTypeSize(typeText)
		}
	}

	return size, elemSize, dimensions, sizeExpr
}

// evaluateNumberLiteral 计算数字字面量
func (d *OOBReadDetector) evaluateNumberLiteral(ctx *core.AnalysisContext, node *sitter.Node) int64 {
	if node == nil || core.SafeType(node) != "number_literal" {
		return 0
	}

	text := ctx.GetSourceText(node)
	// 去掉后缀
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

	return 0
}

// getTypeSize 获取类型大小
func (d *OOBReadDetector) getTypeSize(typeText string) int64 {
	typeSizes := map[string]int64{
		"char":        1,
		"int":         4,
		"long":        8,
		"long long":   8,
		"short":       2,
		"float":       4,
		"double":      8,
		"size_t":      8,
		"uint8_t":     1,
		"uint16_t":    2,
		"uint32_t":    4,
		"uint64_t":    8,
		"int8_t":      1,
		"int16_t":     2,
		"int32_t":     4,
		"int64_t":     8,
		"void*":       8,
		"char*":       8,
		"const char*": 8,
	}

	// 处理指针类型
	if strings.HasSuffix(typeText, "*") {
		return 8
	}

	// 处理 const 修饰符
	typeText = strings.TrimPrefix(typeText, "const ")
	typeText = strings.TrimPrefix(typeText, "volatile ")

	if size, ok := typeSizes[typeText]; ok {
		return size
	}

	return 4 // 默认大小
}

// findArrayAccessExpressions 查找数组访问表达式
func (d *OOBReadDetector) findArrayAccessExpressions(ctx *core.AnalysisContext) []*ArrayAccessExpression {
	var accesses []*ArrayAccessExpression

	// 查找所有 subscript_expression（数组下标访问）
	subscriptQuery := `(subscript_expression) @sub`
	matches, _ := ctx.Query(subscriptQuery)

	for _, match := range matches {
		// 优化1: 跳过预处理注释块中的访问
		if d.isNodeInPreprocessorComment(ctx, match.Node) {
			continue
		}
		access := d.analyzeSubscriptExpression(ctx, match.Node)
		if access != nil {
			accesses = append(accesses, access)
		}
	}

	return accesses
}

// analyzeSubscriptExpression 分析数组下标表达式
func (d *OOBReadDetector) analyzeSubscriptExpression(ctx *core.AnalysisContext, node *sitter.Node) *ArrayAccessExpression {
	// subscript_expression 结构: object[arg]
	// 例如: arr[index]

	if core.SafeChildCount(node) < 2 {
		return nil
	}

	object := core.SafeChild(node, 0) // 被索引的对象（数组）

	// tree-sitter C语法中，subscript_expression的结构可能是：
	//   subscript_expression (object, [, index, ])
	// 或者：
	//   subscript_expression (object, argument_list)
	//
	// 我们需要查找索引节点（跳过括号）
	var indexNode *sitter.Node
	for i := 1; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if child != nil && core.SafeType(child) != "[" && core.SafeType(child) != "]" {
			// 可能是索引表达式或argument_list
			if core.SafeType(child) == "argument_list" {
				// 在argument_list中查找实际的表达式
				for j := 0; j < int(core.SafeChildCount(child)); j++ {
					subChild := core.SafeChild(child, j)
					if core.SafeType(subChild) != "[" && core.SafeType(subChild) != "]" && core.SafeType(subChild) != "," {
						indexNode = subChild
						break
					}
				}
			} else {
				indexNode = child
			}
			break
		}
	}

	if indexNode == nil {
		return nil
	}

	// 获取数组名
	arrayName := d.extractArrayName(ctx, object)
	if arrayName == "" {
		return nil
	}

	// 获取所在函数
	parentFunc := d.findParentFunction(ctx, node)
	funcName := ""
	if parentFunc != nil {
		funcName = d.extractFunctionName(ctx, parentFunc)
	}

	line := int(node.StartPoint().Row) + 1
	indexExpr := ctx.GetSourceText(indexNode)

	// 检查是否是读取操作
	isRead := d.isReadAccess(ctx, node)

	// 处理多维数组
	dimensions := d.countArrayDimensions(ctx, object)
	nestedIndices := d.extractNestedIndices(ctx, node)

	return &ArrayAccessExpression{
		ArrayName:     arrayName,
		IndexNode:     indexNode,
		IndexExpr:     indexExpr,
		AccessNode:    node,
		Function:      funcName,
		Line:          line,
		IsRead:        isRead,
		Dimensions:    dimensions,
		NestedIndices: nestedIndices,
	}
}

// extractArrayName 提取数组名
func (d *OOBReadDetector) extractArrayName(ctx *core.AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return ""
	}

	// 如果是 identifier，直接返回
	if core.SafeType(node) == "identifier" {
		return ctx.GetSourceText(node)
	}

	// 如果是 subscript_expression，递归提取
	if core.SafeType(node) == "subscript_expression" {
		if core.SafeChildCount(node) > 0 {
			return d.extractArrayName(ctx, core.SafeChild(node, 0))
		}
	}

	// 如果是指针解引用
	if core.SafeType(node) == "pointer_expression" || core.SafeType(node) == "dereference_expression" {
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if core.SafeType(child) == "identifier" {
				return ctx.GetSourceText(child)
			}
		}
	}

	return ""
}

// countArrayDimensions 计算数组维度
func (d *OOBReadDetector) countArrayDimensions(ctx *core.AnalysisContext, node *sitter.Node) int {
	dimensions := 0
	current := node

	for current != nil {
		if core.SafeType(current) == "subscript_expression" {
			dimensions++
			if core.SafeChildCount(current) > 0 {
				current = core.SafeChild(current, 0)
			} else {
				break
			}
		} else if core.SafeType(current) == "identifier" {
			break
		} else {
			break
		}
	}

	return dimensions
}

// extractNestedIndices 提取多维数组的嵌套索引
func (d *OOBReadDetector) extractNestedIndices(ctx *core.AnalysisContext, node *sitter.Node) []*sitter.Node {
	var indices []*sitter.Node
	current := node

	for current != nil && core.SafeType(current) == "subscript_expression" {
		if core.SafeChildCount(current) >= 2 {
			arg := core.SafeChild(current, 1)
			if arg != nil && core.SafeType(arg) == "argument_list" {
				// 提取索引表达式
				for i := 0; i < int(core.SafeChildCount(arg)); i++ {
					child := core.SafeChild(arg, i)
					if core.SafeType(child) != "[" && core.SafeType(child) != "]" {
						indices = append(indices, child)
						break
					}
				}
			}
		}

		if core.SafeChildCount(current) > 0 {
			current = core.SafeChild(current, 0)
		} else {
			break
		}
	}

	// 反转顺序，使最外层的索引在前
	for i, j := 0, len(indices)-1; i < j; i, j = i+1, j-1 {
		indices[i], indices[j] = indices[j], indices[i]
	}

	return indices
}

// isReadAccess 检查是否是读取访问
func (d *OOBReadDetector) isReadAccess(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 检查父节点
	parent := node.Parent()
	if parent == nil {
		return false
	}

	// 如果是赋值操作的左值，则是写入
	if core.SafeType(parent) == "assignment_expression" {
		left := core.SafeChild(parent, 0)
		return left != node
	}

	// 如果是 unary_expression 的操作数，检查操作符
	if core.SafeType(parent) == "unary_expression" {
		if core.SafeChildCount(parent) > 0 {
			op := core.SafeChild(parent, 0)
			opText := ctx.GetSourceText(op)
			// ++, -- 是写入
			if opText == "++" || opText == "--" {
				return false
			}
		}
	}

	// 默认认为是读取（因为在表达式中使用）
	return true
}

// findPointerAccessExpressions 查找指针解引用访问
func (d *OOBReadDetector) findPointerAccessExpressions(ctx *core.AnalysisContext) []*ArrayAccessExpression {
	var accesses []*ArrayAccessExpression

	// 查找指针解引用: *ptr 或 *(ptr + offset)
	// 这通常通过 unary_expression 或 pointer_expression 实现

	unaryQuery := `(unary_expression) @unary`
	matches, _ := ctx.Query(unaryQuery)

	for _, match := range matches {
		node := match.Node
		// 检查是否是解引用操作
		if core.SafeChildCount(node) > 0 {
			op := core.SafeChild(node, 0)
			if op != nil && ctx.GetSourceText(op) == "*" {
				operand := core.SafeChild(node, 1)
				if operand != nil {
					access := d.analyzePointerDereference(ctx, node, operand)
					if access != nil {
						accesses = append(accesses, access)
					}
				}
			}
		}
	}

	return accesses
}

// analyzePointerDereference 分析指针解引用
func (d *OOBReadDetector) analyzePointerDereference(ctx *core.AnalysisContext, derefNode, operand *sitter.Node) *ArrayAccessExpression {
	// 提取指针名称（指针变量名）
	pointerName := d.extractArrayName(ctx, operand)
	if pointerName == "" {
		return nil
	}

	// 获取所在函数
	parentFunc := d.findParentFunction(ctx, derefNode)
	funcName := ""
	if parentFunc != nil {
		funcName = d.extractFunctionName(ctx, parentFunc)
	}

	line := int(derefNode.StartPoint().Row) + 1
	isRead := d.isReadAccess(ctx, derefNode)

	return &ArrayAccessExpression{
		ArrayName:  pointerName,
		IndexNode:  nil, // 指针解引用没有索引
		IndexExpr:  "0", // 默认偏移为0
		AccessNode: derefNode,
		Function:   funcName,
		Line:       line,
		IsRead:     isRead,
		Dimensions: 1,
	}
}

// findParentFunction 查找包含节点的函数
func (d *OOBReadDetector) findParentFunction(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
	parent := node.Parent()
	depth := 0
	maxDepth := 50

	for parent != nil && depth < maxDepth {
		if core.SafeType(parent) == "function_definition" {
			return parent
		}
		parent = parent.Parent()
		depth++
	}

	return nil
}

// extractFunctionName 提取函数名
func (d *OOBReadDetector) extractFunctionName(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
	if funcNode == nil {
		return ""
	}

	// 遍历函数定义的子节点
	for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
		child := core.SafeChild(funcNode, i)

		// function_declarator
		if core.SafeType(child) == "function_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "identifier" {
					return ctx.GetSourceText(subChild)
				}
			}
		}

		// pointer_declarator（返回指针的函数）
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

// findInitDeclaratorValue 查找初始化声明符的值
func (d *OOBReadDetector) findInitDeclaratorValue(initDecl *sitter.Node) *sitter.Node {
	if initDecl == nil {
		return nil
	}

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

// extractArrayNameFromDeclarator 从声明符中提取数组名称
func (d *OOBReadDetector) extractArrayNameFromDeclarator(ctx *core.AnalysisContext, declarator *sitter.Node) string {
	// 查找标识符节点
	identifierNode := d.extractIdentifierNodeFromDeclarator(declarator)
	if identifierNode != nil {
		return ctx.GetSourceText(identifierNode)
	}
	return ""
}

// analyzeArrayAccess 分析数组访问
func (d *OOBReadDetector) analyzeArrayAccess(ctx *core.AnalysisContext, access *ArrayAccessExpression) *core.DetectorVulnerability {
	if access == nil {
		return nil
	}

	// 【新增】过滤测试文件
	if d.shouldSkipFile(ctx.Unit.FilePath) {
		return nil
	}

	// 只检测读取操作
	if !access.IsRead {
		return nil
	}

	// 【新增】过滤测试相关的数组访问
	if d.isTestArrayAccess(access.ArrayName, access.IndexExpr) {
		return nil
	}

	// 查找数组信息
	arrayInfo := d.arrayModel.GetArrayInAnyScope(access.ArrayName, access.Function)
	if arrayInfo == nil {
		// 不是已知的数组，可能是指针或其他类型
		return nil
	}

	// 【优化】跳过小数组（小于10个元素）- 误报率较高
	if arrayInfo.Size > 0 && arrayInfo.Size < 10 {
		return nil
	}

	// 【新增】过滤循环上下文中的循环变量索引
	if d.isInLoopContext(ctx, access.AccessNode) {
		// 检查索引是否是常见的循环变量
		if access.IndexNode != nil && access.IndexNode.Type() == "identifier" {
			indexVar := ctx.GetSourceText(access.IndexNode)
			if d.isSafeIndexVariable(indexVar) {
				return nil
			}
		}
	}

	// 【新增】过滤安全的索引变量（不限于循环上下文）
	if access.IndexNode != nil && access.IndexNode.Type() == "identifier" {
		indexVar := ctx.GetSourceText(access.IndexNode)
		if d.isSafeIndexVariable(indexVar) {
			// 对于循环变量，只有在明显越界时才报告
			// 例如：indexValue 为 -1 时通常是错误条件
			indexValue := d.evaluateIndexExpression(ctx, access.IndexNode)
			if indexValue >= 0 && indexValue < arrayInfo.Size {
				return nil
			}
		}
	}

	// 检查索引是否被污染
	isTainted := false
	if d.taintEngine != nil && access.IndexNode != nil {
		if access.IndexNode.Type() == "identifier" {
			// 使用增强的标识符污点检查
			isTainted = d.isIdentifierTainted(ctx, access.IndexNode, access.Function)
		} else {
			isTainted = d.taintEngine.IsTainted(access.IndexNode)
		}
	}

	// 计算索引值
	indexValue := d.evaluateIndexExpression(ctx, access.IndexNode)

	// *** 关键改进1: 当索引值无法确定时(indexValue == -1)，需要更强的证据才报告 ***
	// 大多数 value: -1 的情况是误报，只有在明确有污点且在危险上下文中才报告
	if indexValue == -1 {
		// 索引值无法确定，检查是否真的是污点且在危险上下文中
		if isTainted {
			// 即使是污点，也需要有明确的边界保护缺失且在危险函数中
			if !d.hasBoundsCheck(ctx, access) && d.isInTaintedSinkFunction(ctx, access) {
				// 只有在没有边界检查且在危险函数中才报告
				// 进一步检查：是否在受控循环中（例如 for(i=0; i<n; i++) arr[i]）
				if d.isInControlledLoop(ctx, access) {
					// 在受控循环中，通常是安全的
					return nil
				}
				// 确实是危险场景，但降低置信度 - 继续处理
			} else {
				// 有边界检查或在安全函数中，跳过
				return nil
			}
		} else {
			// 不是污点，只是无法确定值，跳过（避免误报）
			return nil
		}
	}

	// *** 关键改进2: 检查是否在受控循环上下文中 ***
	// 许多OOB访问发生在循环中，但实际上受循环条件控制
	if d.isInControlledLoop(ctx, access) {
		// 受控循环中，检查是否有明显的边界保护
		if d.hasLoopBoundsProtection(ctx, access, arrayInfo.Size) {
			// 有循环边界保护，通常是安全的
			return nil
		}
	}

	// 优化3: 使用置信度评分
	newConfidence := d.assessConfidence(ctx, access)

	// 如果置信度低，跳过此告警（可能是误报）
	if newConfidence == ConfidenceLow {
		return nil
	}

	// 检查是否越界
	isOutOfBounds := false
	confidence := core.ConfidenceMedium
	severity := core.SeverityHigh

	// 优化2: 如果数组大小为 0，可能是动态数组，降低置信度
	if arrayInfo.Size == 0 {
		confidence = core.ConfidenceLow
		return nil // 大小未知的动态数组，跳过
	}

	if indexValue >= 0 {
		// 索引值已知
		if indexValue >= arrayInfo.Size {
			isOutOfBounds = true
			confidence = core.ConfidenceHigh
		}
	} else if indexValue == -1 {
		// 处理已通过前面检查的-1情况（有污点且在危险上下文中）
		isOutOfBounds = true
		confidence = core.ConfidenceLow // 降低置信度
		severity = core.SeverityHigh
	} else {
		// 索引值未知（且不是-1，已处理），需要使用污点分析和启发式判断
		if isTainted {
			// 污点索引：高危
			isOutOfBounds = true
			confidence = core.ConfidenceHigh
			severity = core.SeverityCritical
		} else if arrayInfo.IsTainted {
			// 数组大小被污染：高危
			isOutOfBounds = true
			confidence = core.ConfidenceMedium
			severity = core.SeverityHigh
		} else {
			// 无法静态确定：低置信度
			confidence = core.ConfidenceLow
			// 只在有明确迹象时才报告
		}
	}

	// 如果置信度低，跳过
	if confidence == core.ConfidenceLow {
		return nil
	}

	if isOutOfBounds {
		var message string
		if isTainted {
			message = fmt.Sprintf("Out-of-bounds read: array '%s' accessed with tainted index '%s' (value: %d) at line %d. Array size: %d elements. This allows an attacker to read arbitrary memory.",
				access.ArrayName, access.IndexExpr, indexValue, access.Line, arrayInfo.Size)
		} else {
			message = fmt.Sprintf("Out-of-bounds read: array '%s'[%s] at line %d. Index %d exceeds array bounds (size: %d). This may read unintended memory or cause a crash.",
				access.ArrayName, access.IndexExpr, access.Line, indexValue, arrayInfo.Size)
		}

		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE125,
			message,
			access.AccessNode,
			confidence,
			severity,
		)
		return &vuln
	}

	return nil
}

// analyzePointerAccess 分析指针访问
func (d *OOBReadDetector) analyzePointerAccess(ctx *core.AnalysisContext, access *ArrayAccessExpression) *core.DetectorVulnerability {
	if access == nil || !access.IsRead {
		return nil
	}

	// 指针访问暂不处理（需要更复杂的指针分析）
	return nil
}

// evaluateIndexExpression 计算索引表达式
func (d *OOBReadDetector) evaluateIndexExpression(ctx *core.AnalysisContext, node *sitter.Node) int64 {
	if node == nil {
		return -1 // 未知值
	}

	// 常量
	if core.SafeType(node) == "number_literal" {
		return d.evaluateNumberLiteral(ctx, node)
	}

	// sizeof 表达式
	if core.SafeType(node) == "call_expression" && strings.HasPrefix(ctx.GetSourceText(node), "sizeof") {
		return d.evaluateSizeof(ctx, node)
	}

	// 二元表达式（简化处理）
	if core.SafeType(node) == "binary_expression" {
		left := core.SafeChild(node, 0)
		right := core.SafeChild(node, 2)
		if left != nil && right != nil {
			leftVal := d.evaluateIndexExpression(ctx, left)
			rightVal := d.evaluateIndexExpression(ctx, right)

			op := core.SafeChild(node, 1)
			if op != nil {
				opText := ctx.GetSourceText(op)
				// 处理位运算
				if opText == "&" {
					// 位与运算：x & mask 的范围是 [0, mask]
					// 如果右操作数是常量，可以确定上界
					if rightVal >= 0 {
						// 检查是否是 2^n - 1 的形式（常见的掩码）
						if rightVal == 0 || (rightVal&(rightVal+1)) == 0 {
							// 返回掩码值作为保守的上界
							// 实际访问时会检查 indexValue < arrayInfo.Size
							return rightVal
						}
					}
					// 无法确定掩码值，返回保守估计
					return 0 // 位与运算的最小可能值
				}
				if opText == "|" {
					// 位或运算：至少是 max(leftVal, rightVal)
					if leftVal >= 0 && rightVal >= 0 {
						if leftVal > rightVal {
							return leftVal
						}
						return rightVal
					}
					return -1
				}
				if opText == "^" {
					// 异或运算：范围难以确定，保守返回 -1
					return -1
				}
				if opText == "<<" {
					// 左移：leftVal * (2^rightVal)
					if leftVal >= 0 && rightVal >= 0 && rightVal < 64 {
						return leftVal << uint(rightVal)
					}
					return -1
				}
				if opText == ">>" {
					// 右移：leftVal / (2^rightVal)
					if leftVal >= 0 && rightVal >= 0 && rightVal < 64 {
						return leftVal >> uint(rightVal)
					}
					return -1
				}
				// 算术运算
				if leftVal >= 0 && rightVal >= 0 {
					switch opText {
					case "+":
						return leftVal + rightVal
					case "-":
						return leftVal - rightVal
					case "*":
						return leftVal * rightVal
					case "/":
						if rightVal != 0 {
							return leftVal / rightVal
						}
					case "%":
						if rightVal != 0 {
							return leftVal % rightVal
						}
					}
				}
			}
		}
	}

	// 【新增】处理 identifier 类型 - 查询 callGraph 获取参数值
	if core.SafeType(node) == "identifier" {
		identName := ctx.GetSourceText(node)

		// 获取当前函数名
		currentFunc := d.getCurrentFunctionName(ctx, node)

		// 查询这个标识符是否是函数参数，且有常量值传入
		if currentFunc != "" {
			// 获取函数参数列表
			paramNames := d.getFunctionParameterNames(ctx, currentFunc)
			for i, paramName := range paramNames {
				if paramName == identName {
					// 这是函数参数，查询 callGraph
					possibleValues := d.callGraph.GetPossibleArgValues(currentFunc, i)
					if len(possibleValues) >= 1 {
						// 返回第一个可能的常量值
						return possibleValues[0]
					}
					// 多个值或没有值，返回 -1
				}
			}
		}
	}

	return -1 // 无法静态确定
}

// evaluateSizeof 计算 sizeof 表达式
func (d *OOBReadDetector) evaluateSizeof(ctx *core.AnalysisContext, node *sitter.Node) int64 {
	if core.SafeChildCount(node) < 2 {
		return 0
	}

	arg := core.SafeChild(node, 1)
	text := ctx.GetSourceText(arg)

	typeSizes := map[string]int64{
		"char": 1, "int": 4, "long": 8, "void*": 8, "size_t": 8,
	}

	if size, ok := typeSizes[text]; ok {
		return size
	}

	return 0
}

// getCurrentFunctionName 获取给定节点所在的函数名
func (d *OOBReadDetector) getCurrentFunctionName(ctx *core.AnalysisContext, node *sitter.Node) string {
	// 查找包含该节点的函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, _ := ctx.Query(funcQuery)

	for _, match := range funcMatches {
		// 检查节点是否在这个函数内
		if d.isNodeInScope(node, match.Node) {
			return d.extractFunctionName(ctx, match.Node)
		}
	}

	return ""
}

// getFunctionParameterNames 获取函数的参数名列表
func (d *OOBReadDetector) getFunctionParameterNames(ctx *core.AnalysisContext, funcName string) []string {
	// 查找函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, _ := ctx.Query(funcQuery)

	for _, match := range funcMatches {
		name := d.extractFunctionName(ctx, match.Node)
		if name == funcName {
			// 找到目标函数，提取参数
			return d.extractParameterList(ctx, match.Node)
		}
	}

	return nil
}

// extractParameterList 提取函数参数列表
func (d *OOBReadDetector) extractParameterList(ctx *core.AnalysisContext, funcNode *sitter.Node) []string {
	var paramNames []string

	// function_definition 结构:
	// 0: type
	// 1: declarator (包含函数名和参数)
	// 2: body

	// 找到 declarator
	for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
		child := core.SafeChild(funcNode, i)
		if core.SafeType(child) == "function_declarator" {
			// function_declarator 的子节点:
			// 0: 返回类型/函数名部分
			// 1: parameter_list

			// 查找 parameter_list
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				paramChild := core.SafeChild(child, j)
				if core.SafeType(paramChild) == "parameter_list" {
					// 遍历参数
					for k := 0; k < int(core.SafeChildCount(paramChild)); k++ {
						paramDecl := core.SafeChild(paramChild, k)
						if paramDecl == nil {
							continue
						}

						// parameter_declaration 可能有不同的结构
						// 查找其中的 identifier (参数名)
						paramName := d.extractParameterName(ctx, paramDecl)
						if paramName != "" {
							paramNames = append(paramNames, paramName)
						}
					}
					break
				}
			}
			break
		}
	}

	return paramNames
}

// extractParameterName 从参数声明中提取参数名
func (d *OOBReadDetector) extractParameterName(ctx *core.AnalysisContext, paramDecl *sitter.Node) string {
	// parameter_declaration 结构:
	// 0: type
	// 1: declarator (可选)

	// 首先查找 identifier 类型的子节点（直接声明的参数名）
	for i := 0; i < int(core.SafeChildCount(paramDecl)); i++ {
		child := core.SafeChild(paramDecl, i)
		if child == nil {
			continue
		}

		if core.SafeType(child) == "identifier" {
			return ctx.GetSourceText(child)
		}
	}

	// 如果没有找到 identifier，尝试查找 declarator
	for i := 0; i < int(core.SafeChildCount(paramDecl)); i++ {
		child := core.SafeChild(paramDecl, i)
		if child == nil {
			continue
		}

		childType := core.SafeType(child)
		// 处理各种声明符类型
		if strings.HasSuffix(childType, "_declarator") {
			// 在 declarator 中查找 identifier
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				grandChild := core.SafeChild(child, j)
				if grandChild != nil && core.SafeType(grandChild) == "identifier" {
					return ctx.GetSourceText(grandChild)
				}
			}
		}
	}

	return ""
}

// isIdentifierTainted 检查标识符是否被污染
func (d *OOBReadDetector) isIdentifierTainted(ctx *core.AnalysisContext, identifier *sitter.Node, funcName string) bool {
	if d.taintEngine == nil || identifier == nil || core.SafeType(identifier) != "identifier" {
		return false
	}

	varName := ctx.GetSourceText(identifier)

	// 首先检查变量名是否在污点变量集合中
	if d.taintEngine.IsTainted(identifier) {
		return true
	}

	// 在当前函数中查找该变量的声明
	declQuery := `(declaration) @decl`
	declMatches, _ := ctx.Query(declQuery)

	for _, match := range declMatches {
		varDecl := d.findVariableDeclaration(match.Node, varName, ctx)
		if varDecl != nil {
			// 检查声明节点的污点状态
			if d.taintEngine.IsTainted(varDecl) {
				return true
			}

			// 如果有初始化表达式，检查是否被污染
			initExpr := d.findInitDeclaratorValue(varDecl)
			if initExpr != nil && d.taintEngine.IsTainted(initExpr) {
				return true
			}
		}
	}

	return false
}

// findVariableDeclaration 查找变量声明
func (d *OOBReadDetector) findVariableDeclaration(declNode *sitter.Node, varName string, ctx *core.AnalysisContext) *sitter.Node {
	if declNode == nil {
		return nil
	}

	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if core.SafeType(child) == "init_declarator" {
			declarator := d.findDeclaratorInInitDeclarator(child)
			if declarator != nil {
				identifier := d.extractIdentifierNodeFromDeclarator(declarator)
				if identifier != nil {
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
func (d *OOBReadDetector) findDeclaratorInInitDeclarator(initDecl *sitter.Node) *sitter.Node {
	if initDecl == nil {
		return nil
	}

	for i := 0; i < int(core.SafeChildCount(initDecl)); i++ {
		child := core.SafeChild(initDecl, i)
		if strings.HasSuffix(core.SafeType(child), "_declarator") {
			return child
		}
	}

	return nil
}

// extractIdentifierNodeFromDeclarator 从声明符中提取标识符节点
func (d *OOBReadDetector) extractIdentifierNodeFromDeclarator(declarator *sitter.Node) *sitter.Node {
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
		if found := d.extractIdentifierNodeFromDeclarator(child); found != nil {
			return found
		}
	}

	return nil
}

// ============================================================================
// 优化1: 忽略预处理注释代码 (#if 0, #ifdef DEBUG 等)
// ============================================================================

// preprocessorCache 缓存预处理指令解析结果
var preprocessorCache struct {
	sync.RWMutex
	// key: 文件路径, value: []*preprocessorBlock
	blocks map[string][]*preprocessorBlock
}

type preprocessorBlock struct {
	startLine   int
	endLine     int
	isCommented bool // true 表示被注释掉的代码块（如 #if 0）
}

// isNodeInPreprocessorComment 检查节点是否在预处理注释代码块中
func (d *OOBReadDetector) isNodeInPreprocessorComment(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil || ctx == nil {
		return false
	}

	line := int(node.StartPoint().Row) + 1
	file := ctx.Unit.FilePath

	// 获取该文件的预处理块
	blocks := d.getPreprocessorBlocks(file)
	if blocks == nil {
		// 解析预处理块
		blocks = d.parsePreprocessorBlocks(file)
		d.cachePreprocessorBlocks(file, blocks)
	}

	// 检查是否在任何被注释的块中
	for _, block := range blocks {
		if block.isCommented && line >= block.startLine && line <= block.endLine {
			return true
		}
	}

	return false
}

// getPreprocessorBlocks 从缓存获取预处理块
func (d *OOBReadDetector) getPreprocessorBlocks(file string) []*preprocessorBlock {
	preprocessorCache.RLock()
	defer preprocessorCache.RUnlock()
	if blocks, ok := preprocessorCache.blocks[file]; ok {
		return blocks
	}
	return nil
}

// cachePreprocessorBlocks 缓存预处理块
func (d *OOBReadDetector) cachePreprocessorBlocks(file string, blocks []*preprocessorBlock) {
	preprocessorCache.Lock()
	defer preprocessorCache.Unlock()
	if preprocessorCache.blocks == nil {
		preprocessorCache.blocks = make(map[string][]*preprocessorBlock)
	}
	preprocessorCache.blocks[file] = blocks
}

// parsePreprocessorBlocks 解析文件的预处理指令块
func (d *OOBReadDetector) parsePreprocessorBlocks(file string) []*preprocessorBlock {
	var blocks []*preprocessorBlock

	content, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(content), "\n")

	// 使用栈来匹配 #if/#ifdef/#ifndef 和 #endif
	type blockInfo struct {
		startLine   int
		ifLine      string
		isCommented bool
	}

	var stack []blockInfo
	inMultiLineComment := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// 检测多行注释的开始和结束
		if strings.Contains(trimmed, "/*") {
			inMultiLineComment = true
		}
		if strings.Contains(trimmed, "*/") {
			inMultiLineComment = false
			continue
		}

		// 跳过注释行和代码中的注释
		if inMultiLineComment || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// 检测 #if 0, #ifdef, #ifndef 等条件编译
		if strings.HasPrefix(trimmed, "#if") {
			isCommented := false
			// #if 0 表示注释掉代码块
			if strings.Contains(trimmed, "#if 0") {
				isCommented = true
			}
			// #ifdef DEBUG 等也可能是调试代码
			if strings.Contains(trimmed, "DEBUG") || strings.Contains(trimmed, "debug") {
				isCommented = true
			}

			stack = append(stack, blockInfo{
				startLine:   i + 1, // 行号从1开始
				ifLine:      trimmed,
				isCommented: isCommented,
			})
		}

		// 检测 #endif
		if strings.HasPrefix(trimmed, "#endif") {
			if len(stack) > 0 {
				block := stack[len(stack)-1]
				stack = stack[:len(stack)-1]

				if block.isCommented {
					blocks = append(blocks, &preprocessorBlock{
						startLine:   block.startLine,
						endLine:     i + 1,
						isCommented: true,
					})
				}
			}
		}
	}

	return blocks
}

// ============================================================================
// 优化3: 上下文置信度评分
// ============================================================================

// ConfidenceLevel 置信度级别
type ConfidenceLevel int

const (
	ConfidenceHigh   ConfidenceLevel = 3 // 高置信度 - 很可能是真阳性
	ConfidenceMedium ConfidenceLevel = 2 // 中置信度 - 可能是真阳性
	ConfidenceLow    ConfidenceLevel = 1 // 低置信度 - 可能是误报
	ConfidenceNone   ConfidenceLevel = 0
)

// assessConfidence 评估数组访问的置信度
func (d *OOBReadDetector) assessConfidence(ctx *core.AnalysisContext, access *ArrayAccessExpression) ConfidenceLevel {
	if access == nil {
		return ConfidenceNone
	}

	// 获取数组信息
	arrayInfo := d.arrayModel.GetArrayInAnyScope(access.ArrayName, access.Function)
	if arrayInfo == nil {
		// 数组信息未知，降低置信度
		return ConfidenceMedium
	}

	// 优化3: 检查是否有边界检查
	hasBoundsCheck := d.hasBoundsCheck(ctx, access)
	if hasBoundsCheck {
		return ConfidenceLow // 有边界检查，很可能是误报
	}

	// 检查索引是否是常量
	if access.IndexIsConstant {
		// 常量索引，通常更可靠
		if access.IndexValue >= 0 && access.IndexValue < arrayInfo.Size {
			return ConfidenceLow // 常量在范围内，可能是误报
		}
		return ConfidenceHigh // 常量越界，高置信度
	}

	// 索引是变量，检查是否有污点
	if access.IndexIsTainted {
		return ConfidenceHigh // 污点索引，高风险
	}

	// 索引是变量但未污染
	if arrayInfo.IsTainted {
		return ConfidenceMedium
	}

	return ConfidenceMedium
}

// hasBoundsCheck 检查是否有边界检查保护
func (d *OOBReadDetector) hasBoundsCheck(ctx *core.AnalysisContext, access *ArrayAccessExpression) bool {
	if access == nil {
		return false
	}

	// 在访问点前后查找条件检查
	accessLine := access.Line

	// 向前查找一定行数（通常边界检查在访问点附近）
	searchRange := 20

	// 查找类似的边界检查模式
	boundsCheckPatterns := []string{
		access.ArrayName + " != NULL",
		access.ArrayName + " == NULL",
		"i < " + access.ArrayName,
		"idx < " + access.ArrayName,
		"index < " + access.ArrayName,
		"i >= 0",
		"idx >= 0",
		"i <= " + access.ArrayName,
	}

	content, err := os.ReadFile(ctx.Unit.FilePath)
	if err != nil {
		return false
	}

	lines := strings.Split(string(content), "\n")

	startLine := accessLine - searchRange
	if startLine < 0 {
		startLine = 0
	}
	endLine := accessLine + 5
	if endLine > len(lines) {
		endLine = len(lines)
	}

	for i := startLine; i < endLine; i++ {
		line := lines[i]
		for _, pattern := range boundsCheckPatterns {
			if strings.Contains(line, pattern) {
				// 检查这是否是实际的条件检查
				if strings.Contains(line, "if") || strings.Contains(line, "while") ||
					strings.Contains(line, "&&") || strings.Contains(line, "||") {
					return true
				}
			}
		}
	}

	return false
}

// ============================================================================
// 通用误报过滤函数（参考 NULL pointer 和 Deadlock 检测器改进）
// ============================================================================

// shouldSkipFile 检查是否应该跳过该文件（通用模式）
func (d *OOBReadDetector) shouldSkipFile(filePath string) bool {
	if filePath == "" {
		return false
	}

	// 获取相对路径（移除项目路径前缀）
	relPath := d.extractRelativePath(filePath)
	lowerPath := strings.ToLower(relPath)

	// 1. 测试文件路径模式
	testPatterns := []string{
		"/test/", "/tests/", "/testing/", "/testdata/",
		"_test.", "_test.c", "_test.cc", "_test.cpp",
		"/unit/", "/integration/", "/fuzz/",
		"/example/", "/examples/", "/sample/", "/samples/",
	}
	for _, pattern := range testPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// 1.1 OpenSSL项目特定的测试目录
	opensslTestPatterns := []string{
		"/test/", "/tests/", "/fuzz/", "/apps/test/",
		"test.c", "_test.c", "_test.cc",
	}
	for _, pattern := range opensslTestPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// 1.2 加密算法核心实现（通常包含大量查找表和 intentional OOB 访问）
	cryptoPatterns := []string{
		"/crypto/", "/crypto/aes/", "/crypto/aria/", "/crypto/curve25519/",
		"/crypto/modes/", "/crypto/sha/", "/crypto/evp/",
	}
	for _, pattern := range cryptoPatterns {
		if strings.Contains(lowerPath, pattern) {
			// 对于核心算法实现文件，检查是否是常见的查找表文件
			if strings.Contains(lowerPath, "_core.c") ||
				strings.Contains(lowerPath, "_table.c") ||
				strings.Contains(lowerPath, "_meth.c") ||
				strings.Contains(lowerPath, "aes_core.c") ||
				strings.Contains(lowerPath, "aria.c") {
				return true
			}
		}
	}

	// 2. 架构/平台特定代码
	archPatterns := []string{
		"/arch/", "/platform/", "/os/",
		"/linux/", "/windows/", "/darwin/", "/bsd/",
		"/x86/", "/arm/", "/mips/", "/riscv/",
		"/x86_64/", "/aarch64/", "/arm64/",
	}
	for _, pattern := range archPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// 3. 第三方依赖和第三方代码
	thirdPartyPatterns := []string{
		"/third_party/", "/thirdparty/", "/3rdparty/",
		"/vendor/", "/external/", "/deps/",
		"/contrib/", "/freedesktop/", "/gnome/",
	}
	for _, pattern := range thirdPartyPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// 4. 构建系统、工具生成的代码
	buildPatterns := []string{
		"/build/", "/cmake-build/", "/out/", "/gen/",
		"/generated/", "/.gendoc/", "/.proto/",
		"_pb2.c", "_pb2.go", // protobuf 生成
		"_generated.", // 自动生成
	}
	for _, pattern := range buildPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	return false
}

// extractRelativePath 提取相对路径（智能检测项目根目录）
func (d *OOBReadDetector) extractRelativePath(filePath string) string {
	if filePath == "" {
		return filePath
	}

	// 获取调用栈信息来检测项目根目录
	_, ownFile, _, ok := runtime.Caller(0)
	if ok {
		// 我们在 gosast/internal/detectors/ 目录下
		// 向上查找项目根目录（包含 go.mod 的目录）
		projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(ownFile)))
		if strings.HasSuffix(projectRoot, "gosast") {
			// 检测到 gosast 项目根目录
			if strings.HasPrefix(filePath, projectRoot) {
				return filePath[len(projectRoot)+1:]
			}
		}
	}

	// 通用检测：查找常见的项目根目录标记
	parts := strings.Split(filepath.ToSlash(filePath), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		// 常见的项目根目录标记
		if parts[i] == "src" || parts[i] == "lib" ||
			parts[i] == "app" || parts[i] == "cmd" {
			if i < len(parts)-1 {
				return strings.Join(parts[i+1:], "/")
			}
		}
	}

	// 默认返回文件名
	return filepath.Base(filePath)
}

// isSafeIndexVariable 检查索引变量是否是安全模式（通用）
func (d *OOBReadDetector) isSafeIndexVariable(indexVar string) bool {
	if indexVar == "" {
		return false
	}

	lowerName := strings.ToLower(indexVar)

	// 1. 循环变量（最常见的误报来源）
	loopVars := []string{"i", "j", "k", "ii", "jj", "kk", "idx", "index", "n", "m"}
	for _, v := range loopVars {
		if lowerName == v || strings.HasSuffix(lowerName, "_"+v) {
			return true
		}
	}

	// 2. 测试相关变量名
	testPatterns := []string{
		"test", "mock", "fake", "dummy", "stub",
		"temp", "tmp", "temporary", "example",
		"sample", "demo", "fixture", "expected",
	}
	for _, pattern := range testPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	// 3. expected 相关变量（测试中常用的期望值）
	expectedPatterns := []string{
		"expected_", "expect_", "assert_", "check_",
		"correct_", "right_", "valid_",
	}
	for _, pattern := range expectedPatterns {
		if strings.HasPrefix(lowerName, pattern) {
			return true
		}
	}

	// 4. 循环计数器模式（如 i, i1, i2, idx_1, idx_2 等）
	if len(indexVar) == 1 {
		// 单字母变量通常是循环变量
		if indexVar[0] >= 'i' && indexVar[0] <= 'z' {
			return true
		}
	}

	// 5. 带数字的索引变量（i1, i2, idx1, idx2 等）
	if len(indexVar) > 1 {
		lastChar := indexVar[len(indexVar)-1]
		if lastChar >= '0' && lastChar <= '9' {
			// 检查前缀是否是常见的索引变量名
			prefix := indexVar[:len(indexVar)-1]
			if prefix == "i" || prefix == "j" || prefix == "k" ||
				prefix == "idx" || prefix == "index" ||
				strings.HasSuffix(prefix, "_") {
				return true
			}
		}
	}

	return false
}

// isTestArrayAccess 检查是否是测试相关的数组访问（通用模式）
func (d *OOBReadDetector) isTestArrayAccess(arrayName, indexExpr string) bool {
	if arrayName == "" || indexExpr == "" {
		return false
	}

	lowerArray := strings.ToLower(arrayName)
	lowerIndex := strings.ToLower(indexExpr)

	// 1. 测试数据数组
	testArrayPatterns := []string{
		"test", "mock", "fake", "dummy", "stub",
		"sample", "example", "fixture",
		"expected", "correct", "right", "valid",
	}
	for _, pattern := range testArrayPatterns {
		if strings.Contains(lowerArray, pattern) {
			return true
		}
	}

	// 2. 特定的测试数组命名模式
	if strings.HasPrefix(lowerArray, "test_") ||
		strings.HasPrefix(lowerArray, "mock_") ||
		strings.HasPrefix(lowerArray, "expected_") {
		return true
	}

	// 3. 测试相关的索引表达式
	if strings.Contains(lowerIndex, "test") ||
		strings.Contains(lowerIndex, "mock") ||
		strings.Contains(lowerIndex, "expected") {
		return true
	}

	return false
}

// isInLoopContext 检查访问是否在循环上下文中（启发式）
func (d *OOBReadDetector) isInLoopContext(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 向上查找父节点，检查是否在循环中
	parent := node.Parent()
	depth := 0
	maxDepth := 10

	for parent != nil && depth < maxDepth {
		nodeType := core.SafeType(parent)

		// 检查是否在循环语句中
		if nodeType == "for_statement" ||
			nodeType == "while_statement" ||
			nodeType == "do_statement" {
			return true
		}

		parent = parent.Parent()
		depth++
	}

	return false
}

// isHeaderFile 检查文件是否是头文件（通用编程模式）
// 头文件通常包含宏定义和接口声明，不是实际执行代码
func (d *OOBReadDetector) isHeaderFile(filePath string) bool {
	if filePath == "" {
		return false
	}

	// 获取文件名
	fileName := filepath.Base(filePath)
	lowerName := strings.ToLower(fileName)

	// 常见的头文件扩展名（编程语言通用symbol）
	headerExts := []string{".h", ".hpp", ".hxx", ".hh", ".h++", ".h.in"}
	for _, ext := range headerExts {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}

	return false
}

// isInTaintedSinkFunction 检查访问是否在污点汇聚函数中（例如处理用户输入的函数）
// 如果在通用算法函数中，即使有污点也通常是安全的
func (d *OOBReadDetector) isInTaintedSinkFunction(ctx *core.AnalysisContext, access *ArrayAccessExpression) bool {
	if access == nil || access.Function == "" {
		return false
	}

	funcName := strings.ToLower(access.Function)

	// 1. 用户输入处理函数（高危）
	sinkFunctions := []string{
		"read", "recv", "fgets", "gets", "scanf", "fscanf",
		"parse", "decode", "decrypt", "unpack",
		"process_input", "handle_request", "user_",
	}
	for _, sink := range sinkFunctions {
		if strings.Contains(funcName, sink) {
			return true
		}
	}

	// 2. 通用算法函数（安全，即使有污点）
	safeFunctions := []string{
		"encrypt", "decrypt", "transform", "compute",
		"update", "finalize", "init", "cleanup",
		"crypto_", "cipher_", "hash_", "digest_",
		"aes_", "aria_", "sha_", "md5_", "evp_",
	}
	for _, safe := range safeFunctions {
		if strings.HasPrefix(funcName, safe) {
			return false
		}
	}

	// 默认：不在明显的安全函数中，可能是真问题
	return true
}

// ============================================================================
// 改进2: 受控循环检测
// ============================================================================

// isInControlledLoop 检查数组访问是否在受控循环中
// 受控循环是指有明确边界条件的循环（例如 for(i=0; i<size; i++)）
func (d *OOBReadDetector) isInControlledLoop(ctx *core.AnalysisContext, access *ArrayAccessExpression) bool {
	if access == nil || access.IndexNode == nil {
		return false
	}

	// 提取索引变量名
	indexVar := ""
	if core.SafeType(access.IndexNode) == "identifier" {
		indexVar = ctx.GetSourceText(access.IndexNode)
	} else {
		// 对于复杂表达式，尝试提取主变量
		indexVar = d.extractMainVariable(ctx, access.IndexNode)
	}

	if indexVar == "" {
		return false
	}

	// 向上查找父节点，检查是否在循环中
	parent := access.AccessNode.Parent()
	depth := 0
	maxDepth := 15

	for parent != nil && depth < maxDepth {
		nodeType := core.SafeType(parent)

		// 检查是否在循环语句中
		if nodeType == "for_statement" || nodeType == "while_statement" || nodeType == "do_statement" {
			// 检查循环条件是否控制该索引变量
			if d.doesLoopControlVariable(ctx, parent, indexVar) {
				return true
			}
		}

		parent = parent.Parent()
		depth++
	}

	return false
}

// extractMainVariable 从表达式中提取主变量名
// 例如：从 "symbol & 0xff" 中提取 "symbol"
func (d *OOBReadDetector) extractMainVariable(ctx *core.AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return ""
	}

	nodeType := core.SafeType(node)

	// 标识符直接返回
	if nodeType == "identifier" {
		return ctx.GetSourceText(node)
	}

	// 二元表达式：提取左操作数（通常是变量）
	if nodeType == "binary_expression" {
		left := core.SafeChild(node, 0)
		if left != nil && core.SafeType(left) == "identifier" {
			return ctx.GetSourceText(left)
		}
	}

	return ""
}

// doesLoopControlVariable 检查循环条件是否控制该变量
func (d *OOBReadDetector) doesLoopControlVariable(ctx *core.AnalysisContext, loopNode *sitter.Node, varName string) bool {
	if loopNode == nil || varName == "" {
		return false
	}

	loopType := core.SafeType(loopNode)

	switch loopType {
	case "for_statement":
		// for循环：检查条件部分
		// for_statement 结构: for(init; condition; increment)
		condition := core.SafeChildByFieldName(loopNode, "condition")
		if condition != nil {
			condText := ctx.GetSourceText(condition)
			// 检查条件中是否包含该变量的比较
			// 例如: i < n, i >= 0, i <= size 等
			if d.hasVariableComparison(condText, varName) {
				return true
			}
		}

	case "while_statement":
		// while循环：检查条件
		condition := core.SafeChildByFieldName(loopNode, "condition")
		if condition != nil {
			condText := ctx.GetSourceText(condition)
			if d.hasVariableComparison(condText, varName) {
				return true
			}
		}

	case "do_statement":
		// do-while循环：检查条件
		condition := core.SafeChildByFieldName(loopNode, "condition")
		if condition != nil {
			condText := ctx.GetSourceText(condition)
			if d.hasVariableComparison(condText, varName) {
				return true
			}
		}
	}

	return false
}

// hasVariableComparison 检查条件文本中是否包含变量的边界比较
func (d *OOBReadDetector) hasVariableComparison(condText, varName string) bool {
	if condText == "" || varName == "" {
		return false
	}

	// 常见的边界比较模式（编程语言通用符号）
	comparisonPatterns := []string{
		varName + " < ",  // 小于
		varName + " <= ", // 小于等于
		varName + " > ",  // 大于
		varName + " >= ", // 大于等于
		" < " + varName,  // 反向比较
		" <= " + varName,
		" > " + varName,
		" >= " + varName,
		varName + " <", // 无空格版本
		varName + " <=",
		varName + " >",
		varName + " >=",
	}

	for _, pattern := range comparisonPatterns {
		if strings.Contains(condText, pattern) {
			return true
		}
	}

	return false
}

// hasLoopBoundsProtection 检查循环是否有边界保护
// 例如: for(i=0; i<size && i<MAX; i++) 中的 i<MAX 就是额外保护
func (d *OOBReadDetector) hasLoopBoundsProtection(ctx *core.AnalysisContext, access *ArrayAccessExpression, arraySize int64) bool {
	if access == nil || access.IndexNode == nil {
		return false
	}

	indexVar := ""
	if core.SafeType(access.IndexNode) == "identifier" {
		indexVar = ctx.GetSourceText(access.IndexNode)
	} else {
		indexVar = d.extractMainVariable(ctx, access.IndexNode)
	}

	if indexVar == "" {
		return false
	}

	// 查找包含该访问的循环
	parent := access.AccessNode.Parent()
	depth := 0
	maxDepth := 15

	for parent != nil && depth < maxDepth {
		nodeType := core.SafeType(parent)

		if nodeType == "for_statement" || nodeType == "while_statement" || nodeType == "do_statement" {
			condition := core.SafeChildByFieldName(parent, "condition")
			if condition != nil {
				condText := ctx.GetSourceText(condition)

				// 检查是否有 AND 连接的多个条件（双重保护）
				if strings.Contains(condText, "&&") || strings.Contains(condText, " and ") {
					// 提取所有条件部分
					conditions := strings.FieldsFunc(condText, func(r rune) bool {
						return r == '&' || r == ';'
					})

					// 检查是否有涉及数组大小的边界检查
					for _, cond := range conditions {
						cond = strings.TrimSpace(cond)
						// 检查是否有常量边界（例如 i<256）
						if d.hasConstantBoundsCheck(cond, indexVar, arraySize) {
							return true
						}
					}
				}
			}
			break // 找到循环后就停止
		}

		parent = parent.Parent()
		depth++
	}

	return false
}

// hasConstantBoundsCheck 检查条件中是否有常量边界检查
func (d *OOBReadDetector) hasConstantBoundsCheck(condText, varName string, arraySize int64) bool {
	if condText == "" || varName == "" {
		return false
	}

	// 检查常见的常量边界模式
	// 例如: i<256, i>=0, i<=255 等
	patterns := []string{
		varName + " < ", // 变量 < 常量
		varName + " <= ",
		varName + " >= ",
		" < " + varName, // 常量 < 变量
		" <= " + varName,
	}

	for _, pattern := range patterns {
		if strings.Contains(condText, pattern) {
			// 尝试提取常量值
			parts := strings.Split(condText, pattern)
			if len(parts) > 1 {
				constPart := strings.TrimSpace(parts[1])
				// 简单检查是否以数字开头
				if len(constPart) > 0 && (constPart[0] >= '0' && constPart[0] <= '9') {
					return true
				}
			}
		}
	}

	return false
}
