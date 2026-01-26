package detectors

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// SharedVariable 共享变量信息
type SharedVariable struct {
	Name        string           // 变量名
	IsGlobal    bool             // 是否为全局变量
	IsStatic    bool             // 是否为静态变量
	IsConst     bool             // 是否为只读
	Type        string           // 变量类型
	Declaration *sitter.Node     // 声明节点
	Accesses    []VariableAccess // 访问记录
}

// VariableAccess 变量访问记录
type VariableAccess struct {
	Function    string       // 所在函数
	Line        int          // 行号
	AccessType  string       // 访问类型: "read", "write", "read_modify_write"
	Node        *sitter.Node // AST节点
	IsProtected bool         // 是否被锁保护
	GuardLocks  []string     // 保护该访问的锁列表
}

// ThreadCreation 线程创建信息
type ThreadCreation struct {
	Function     string       // 所在函数
	Line         int          // 行号
	Node         *sitter.Node // AST节点
	ThreadFunc   string       // 线程函数名
	IsLambda     bool         // 是否为lambda表达式
	CapturedVars []string     // 捕获的变量
}

// SyncProtection 同步保护信息
type SyncProtection struct {
	Type      string // "mutex", "lock_guard", "atomic", "scoped_lock"
	LockVar   string // 锁变量名
	LineStart int    // 保护范围起始行
	LineEnd   int    // 保护范围结束行
	Function  string // 所在函数
}

// DataRaceDetector 数据竞争检测器
type DataRaceDetector struct {
	*core.BaseDetector
	sharedVars      map[string]*SharedVariable
	threadCreations []ThreadCreation
	escapeMap       map[string][]ThreadCreation
}

// NewDataRaceDetector 创建数据竞争检测器
func NewDataRaceDetector() *DataRaceDetector {
	return &DataRaceDetector{
		BaseDetector: core.NewBaseDetector(
			"Data Race Detector",
			"Detects data races in multithreaded code using escape analysis and thread interleaving simulation (CWE-362)",
		),
		sharedVars:      make(map[string]*SharedVariable),
		threadCreations: make([]ThreadCreation, 0),
		escapeMap:       make(map[string][]ThreadCreation),
	}
}

// Run 运行检测器
func (d *DataRaceDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 【修复】每个文件开始时清空状态，避免跨文件污染
	d.sharedVars = make(map[string]*SharedVariable)
	d.threadCreations = make([]ThreadCreation, 0)
	d.escapeMap = make(map[string][]ThreadCreation)

	// 1. 收集共享变量（全局、静态、const）
	d.collectSharedVariables(ctx)

	// 2. 查找线程创建点（std::thread, pthread_create）
	d.findThreadCreations(ctx)

	// 如果没有线程创建，不需要检测数据竞争
	if len(d.threadCreations) == 0 {
		return vulns, nil
	}

	// 3. 逃逸分析（变量如何传递到线程）
	d.analyzeEscapePaths(ctx)

	// 4. 收集所有访问（读/写/读-改-写）
	d.collectAllVariableAccesses(ctx)

	// 5. 检测同步保护（锁、原子操作）
	d.detectProtection(ctx)

	// 6. 识别数据竞争（冲突访问 + 无保护）
	for varName, sharedVar := range d.sharedVars {
		// 跳过只读变量
		if sharedVar.IsConst {
			continue
		}

		// 检查是否逃逸到多线程
		threads, escapes := d.escapeMap[varName]
		if !escapes || len(threads) < 2 {
			// 没有逃逸到多线程，跳过
			continue
		}

		// 检查是否有数据竞争
		if d.hasDataRace(sharedVar) {
			vuln := d.createRaceVulnerability(ctx, sharedVar, threads)
			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

// collectSharedVariables 收集共享变量（全局、静态、const）
func (d *DataRaceDetector) collectSharedVariables(ctx *core.AnalysisContext) {
	// 只查找直接在 translation_unit 下的声明（真正的全局变量）
	// 查找有初始化器的全局变量
	globalQuery := `(translation_unit
		(declaration
			declarator: (init_declarator
				declarator: (identifier) @name
			) @initdecl
		) @decl
	)`

	matches, err := ctx.Query(globalQuery)
	if err == nil {
		for _, match := range matches {
			declNode := match.Node

			// 提取变量名
			nameMatch := match.Captures["name"]
			if nameMatch == nil {
				continue
			}
			varName := ctx.GetSourceText(nameMatch)

			// 检查是否是 const
			isConst := d.hasConstSpecifier(ctx, declNode)

			// 提取类型
			varType := d.extractVariableType(ctx, declNode)

			d.sharedVars[varName] = &SharedVariable{
				Name:        varName,
				IsGlobal:    true,
				IsStatic:    false,
				IsConst:     isConst,
				Type:        varType,
				Declaration: declNode,
				Accesses:    make([]VariableAccess, 0),
			}
		}
	}

	// 查找无初始化器的全局变量
	globalQuery2 := `(translation_unit
		(declaration
			declarator: (identifier) @name
		) @decl
	)`

	matches2, err := ctx.Query(globalQuery2)
	if err == nil {
		for _, match := range matches2 {
			declNode := match.Node

			// 提取变量名
			nameMatch := match.Captures["name"]
			if nameMatch == nil {
				continue
			}
			varName := ctx.GetSourceText(nameMatch)

			// 如果已存在，跳过
			if d.sharedVars[varName] != nil {
				continue
			}

			// 检查是否是 const
			isConst := d.hasConstSpecifier(ctx, declNode)

			// 提取类型
			varType := d.extractVariableType(ctx, declNode)

			d.sharedVars[varName] = &SharedVariable{
				Name:        varName,
				IsGlobal:    true,
				IsStatic:    false,
				IsConst:     isConst,
				Type:        varType,
				Declaration: declNode,
				Accesses:    make([]VariableAccess, 0),
			}
		}
	}

	// 查找静态变量
	staticQuery := `(declaration
		(storage_class_specifier
			(type_identifier) @spec
			#eq? @spec "static"
		)
		declarator: (identifier) @name
	) @decl`

	staticMatches, err := ctx.Query(staticQuery)
	if err == nil {
		for _, match := range staticMatches {
			declNode := match.Node

			// 提取变量名
			nameMatch := match.Captures["name"]
			if nameMatch == nil {
				continue
			}
			varName := ctx.GetSourceText(nameMatch)

			// 如果已存在，跳过
			if d.sharedVars[varName] != nil {
				continue
			}

			// 检查是否是 const
			isConst := d.hasConstSpecifier(ctx, declNode)

			// 提取类型
			varType := d.extractVariableType(ctx, declNode)

			d.sharedVars[varName] = &SharedVariable{
				Name:        varName,
				IsGlobal:    false,
				IsStatic:    true,
				IsConst:     isConst,
				Type:        varType,
				Declaration: declNode,
				Accesses:    make([]VariableAccess, 0),
			}
		}
	}
}

// findThreadCreations 查找线程创建点
func (d *DataRaceDetector) findThreadCreations(ctx *core.AnalysisContext) {
	// C++ std::thread 模式 - 匹配 std::thread t1(func) 声明
	cppThreadQuery := `(declaration
		type: (qualified_identifier) @typeid
		declarator: (function_declarator
			parameters: (parameter_list) @params
		)
	) @decl`

	matches, err := ctx.Query(cppThreadQuery)
	if err == nil {
		for _, match := range matches {
			declNode := match.Node
			typeidMatch := match.Captures["typeid"]
			paramsMatch := match.Captures["params"]

			// 检查类型是否包含 "thread"
			if typeidMatch == nil {
				continue
			}
			typeText := ctx.GetSourceText(typeidMatch)
			if !contains(typeText, "thread") {
				continue
			}

			// 获取所在函数
			parentFunc := d.findParentFunction(ctx, declNode)
			funcName := ""
			if parentFunc != nil {
				funcName = d.extractFunctionName(ctx, parentFunc)
			}

			line := int(declNode.StartPoint().Row) + 1

			// 提取线程函数名和捕获的变量
			threadFunc := ""
			capturedVars := []string{}
			isLambda := false

			if paramsMatch != nil {
				// 检查第一个参数是否是 lambda
				firstParam := d.getFirstArgument(paramsMatch)
				if firstParam != nil {
					// parameter_declaration -> identifier/type_identifier
					if core.SafeType(firstParam) == "parameter_declaration" {
						// 从parameter_declaration中提取identifier
						for i := 0; i < int(core.SafeChildCount(firstParam)); i++ {
							child := core.SafeChild(firstParam, i)
							if child != nil && (core.SafeType(child) == "identifier" || core.SafeType(child) == "type_identifier") {
								threadFunc = ctx.GetSourceText(child)
								break
							}
						}
					} else if core.SafeType(firstParam) == "lambda_expression" {
						isLambda = true
						capturedVars = d.extractLambdaCaptures(ctx, firstParam)
					} else if core.SafeType(firstParam) == "identifier" {
						threadFunc = ctx.GetSourceText(firstParam)
					}
				}
			}

			d.threadCreations = append(d.threadCreations, ThreadCreation{
				Function:     funcName,
				Line:         line,
				Node:         declNode,
				ThreadFunc:   threadFunc,
				IsLambda:     isLambda,
				CapturedVars: capturedVars,
			})
		}
	}

	// pthread_create 模式
	pthreadQuery := `(call_expression
		function: (identifier) @func
		#eq? @func "pthread_create"
		arguments: (argument_list) @args
	) @call`

	pthreadMatches, err := ctx.Query(pthreadQuery)
	if err == nil {
		for _, match := range pthreadMatches {
			callExpr := match.Node
			argsMatch := match.Captures["args"]

			// 获取所在函数
			parentFunc := d.findParentFunction(ctx, callExpr)
			funcName := ""
			if parentFunc != nil {
				funcName = d.extractFunctionName(ctx, parentFunc)
			}

			line := int(callExpr.StartPoint().Row) + 1

			// 提取线程函数名（第3个参数）
			threadFunc := ""
			if argsMatch != nil {
				args := d.extractArguments(argsMatch)
				if len(args) >= 3 {
					// pthread_create(&tid, NULL, func, arg)
					// 第3个参数是线程函数
					threadFunc = ctx.GetSourceText(args[2])
				}
			}

			d.threadCreations = append(d.threadCreations, ThreadCreation{
				Function:   funcName,
				Line:       line,
				Node:       callExpr,
				ThreadFunc: threadFunc,
				IsLambda:   false,
			})
		}
	}
}

// analyzeEscapePaths 分析变量如何逃逸到线程
func (d *DataRaceDetector) analyzeEscapePaths(ctx *core.AnalysisContext) {
	// 全局变量自动逃逸到所有线程
	for varName := range d.sharedVars {
		if d.sharedVars[varName].IsGlobal {
			d.escapeMap[varName] = d.threadCreations
		}
	}

	// Lambda 捕获的变量
	for _, thread := range d.threadCreations {
		if thread.IsLambda {
			for _, varName := range thread.CapturedVars {
				if d.sharedVars[varName] != nil {
					d.escapeMap[varName] = append(d.escapeMap[varName], thread)
				}
			}
		}
	}

	// TODO: 分析通过指针/引用传递的变量
	// 这需要更复杂的跨文件分析
}

// collectAllVariableAccesses 收集所有变量访问
func (d *DataRaceDetector) collectAllVariableAccesses(ctx *core.AnalysisContext) {
	// 查找所有标识符使用
	query := `(identifier) @id`
	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	for _, match := range matches {
		idNode := match.Node
		varName := ctx.GetSourceText(idNode)

		// 只关心我们跟踪的共享变量
		if d.sharedVars[varName] == nil {
			continue
		}

		// 获取所在函数
		parentFunc := d.findParentFunction(ctx, idNode)
		funcName := ""
		if parentFunc != nil {
			funcName = d.extractFunctionName(ctx, parentFunc)
		}

		line := int(idNode.StartPoint().Row) + 1

		// 确定访问类型
		accessType := d.determineAccessType(ctx, idNode)

		d.sharedVars[varName].Accesses = append(d.sharedVars[varName].Accesses, VariableAccess{
			Function:    funcName,
			Line:        line,
			AccessType:  accessType,
			Node:        idNode,
			IsProtected: false,
			GuardLocks:  []string{},
		})
	}
}

// detectProtection 检测同步保护
func (d *DataRaceDetector) detectProtection(ctx *core.AnalysisContext) {
	// 查找所有 lock_guard 声明 - 匹配 std::lock_guard<std::mutex> lock(mutex)
	lockGuardQuery := `(declaration
		type: (qualified_identifier) @typeid
		declarator: (function_declarator
			parameters: (parameter_list) @params
		)
	) @decl`

	matches, err := ctx.Query(lockGuardQuery)
	if err != nil {
		return
	}

	// 收集所有锁保护区域
	protections := []SyncProtection{}
	for _, match := range matches {
		declNode := match.Node
		typeidMatch := match.Captures["typeid"]
		paramsMatch := match.Captures["params"]

		// 检查类型是否包含 "lock_guard" 或 "unique_lock" 或 "scoped_lock"
		if typeidMatch == nil {
			continue
		}
		typeText := ctx.GetSourceText(typeidMatch)
		if !contains(typeText, "lock_guard") && !contains(typeText, "unique_lock") && !contains(typeText, "scoped_lock") {
			continue
		}

		// 获取所在函数
		parentFunc := d.findParentFunction(ctx, declNode)
		funcName := ""
		if parentFunc != nil {
			funcName = d.extractFunctionName(ctx, parentFunc)
		}

		lineStart := int(declNode.StartPoint().Row) + 1

		// 提取锁变量名
		lockVar := ""
		if paramsMatch != nil {
			lockVarNode := d.getFirstArgument(paramsMatch)
			if lockVarNode != nil {
				lockVar = ctx.GetSourceText(lockVarNode)
			}
		}

		// 估算保护范围（简化：到作用域结束）
		lineEnd := d.estimateScopeEnd(ctx, declNode)

		protections = append(protections, SyncProtection{
			Type:      "lock_guard",
			LockVar:   lockVar,
			LineStart: lineStart,
			LineEnd:   lineEnd,
			Function:  funcName,
		})
	}

	// 标记被保护的访问
	for varName := range d.sharedVars {
		for i, access := range d.sharedVars[varName].Accesses {
			for _, protection := range protections {
				if d.isAccessProtected(access, protection) {
					d.sharedVars[varName].Accesses[i].IsProtected = true
					d.sharedVars[varName].Accesses[i].GuardLocks = append(
						d.sharedVars[varName].Accesses[i].GuardLocks,
						protection.LockVar,
					)
				}
			}
		}
	}
}

// hasDataRace 检查是否存在数据竞争
func (d *DataRaceDetector) hasDataRace(sharedVar *SharedVariable) bool {
	// 统计每个线程函数被创建了多少次
	threadFuncCounts := make(map[string]int)
	for _, tc := range d.threadCreations {
		if tc.ThreadFunc != "" {
			threadFuncCounts[tc.ThreadFunc]++
		}
	}

	// 只收集在线程函数内的访问
	var writes []VariableAccess
	var reads []VariableAccess

	for _, access := range sharedVar.Accesses {
		// 跳过匿名函数的访问（初始化等）
		if access.Function == "" {
			continue
		}

		// 只检查在线程函数中的访问
		if threadFuncCounts[access.Function] == 0 {
			continue
		}

		if access.AccessType == "write" || access.AccessType == "read_modify_write" {
			writes = append(writes, access)
		} else {
			reads = append(reads, access)
		}
	}

	// 如果没有写访问，不会有数据竞争
	if len(writes) == 0 {
		return false
	}

	// 检查写-写冲突
	for _, write := range writes {
		// 如果这个函数被多次创建，并且写访问没有保护，就是数据竞争
		if threadFuncCounts[write.Function] >= 2 && !write.IsProtected {
			return true
		}
	}

	// 检查读-写冲突
	for _, write := range writes {
		for _, read := range reads {
			// 如果读和写在不同的函数中，并且没有被同一锁保护
			if write.Function != read.Function && !d.haveSameProtection(write, read) {
				return true
			}
		}
	}

	return false
}

// getMapKeys 获取map的所有key
func getMapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// createRaceVulnerability 创建数据竞争漏洞报告
func (d *DataRaceDetector) createRaceVulnerability(
	ctx *core.AnalysisContext,
	sharedVar *SharedVariable,
	threads []ThreadCreation,
) core.DetectorVulnerability {

	// 构建访问位置信息
	var accessInfo []string
	for _, access := range sharedVar.Accesses {
		if !access.IsProtected {
			accessInfo = append(accessInfo,
				fmt.Sprintf("%s() at line %d (%s)", access.Function, access.Line, access.AccessType))
		}
	}

	message := fmt.Sprintf("Data race detected on shared variable '%s'. Multiple threads access this variable without proper synchronization. Type: %s. Locations: %v",
		sharedVar.Name, sharedVar.Type, accessInfo)

	// 使用第一个访问点作为位置
	var locationNode *sitter.Node
	if len(sharedVar.Accesses) > 0 {
		locationNode = sharedVar.Accesses[0].Node
	} else {
		locationNode = sharedVar.Declaration
	}

	return d.BaseDetector.CreateVulnerability(
		core.CWE362, // CWE-362: Race Condition
		message,
		locationNode,
		core.ConfidenceHigh,
		core.SeverityCritical,
	)
}

// ========== 辅助方法 ==========

// hasConstSpecifier 检查声明是否有 const 限定符
func (d *DataRaceDetector) hasConstSpecifier(ctx *core.AnalysisContext, declNode *sitter.Node) bool {
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if child == nil {
			continue
		}

		// 检查是否是 type_qualifier
		if core.SafeType(child) == "type_qualifier" {
			text := ctx.GetSourceText(child)
			if strings.Contains(text, "const") {
				return true
			}
		}
	}
	return false
}

// extractVariableType 提取变量类型
func (d *DataRaceDetector) extractVariableType(ctx *core.AnalysisContext, declNode *sitter.Node) string {
	// 查找类型节点
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if child == nil {
			continue
		}

		// 跳过声明符
		if core.SafeType(child) == "declarator" || core.SafeType(child) == "init_declarator" {
			continue
		}

		// 类型声明
		text := ctx.GetSourceText(child)
		// 清理
		text = strings.TrimSpace(text)
		if len(text) > 50 {
			text = text[:50] + "..."
		}
		return text
	}
	return "unknown"
}

// findParentFunction 查找包含节点的函数
func (d *DataRaceDetector) findParentFunction(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
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
func (d *DataRaceDetector) extractFunctionName(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
	if funcNode == nil {
		return ""
	}

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
		// 处理 pointer_declarator（返回指针的函数）
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
			}
		}
	}
	return ""
}

// determineAccessType 确定访问类型
func (d *DataRaceDetector) determineAccessType(ctx *core.AnalysisContext, idNode *sitter.Node) string {
	parent := idNode.Parent()

	// 检查是否是赋值操作的左侧（写）
	if parent != nil && core.SafeType(parent) == "assignment_expression" {
		leftChild := core.SafeChild(parent, 0)
		if leftChild == idNode {
			return "write"
		}
	}

	// 检查是否是自增/自减操作（读-改-写）
	if parent != nil && core.SafeType(parent) == "update_expression" {
		return "read_modify_write"
	}

	// 默认是读
	return "read"
}

// getFirstArgument 获取参数列表的第一个参数
func (d *DataRaceDetector) getFirstArgument(argsNode *sitter.Node) *sitter.Node {
	if argsNode == nil {
		return nil
	}

	for i := 0; i < int(core.SafeChildCount(argsNode)); i++ {
		child := core.SafeChild(argsNode, i)
		if child == nil {
			continue
		}

		// 跳过标点符号
		if core.SafeType(child) == "," || core.SafeType(child) == "(" || core.SafeType(child) == ")" {
			continue
		}

		return child
	}

	return nil
}

// extractArguments 提取所有参数
func (d *DataRaceDetector) extractArguments(argsNode *sitter.Node) []*sitter.Node {
	var args []*sitter.Node

	if argsNode == nil {
		return args
	}

	for i := 0; i < int(core.SafeChildCount(argsNode)); i++ {
		child := core.SafeChild(argsNode, i)
		if child == nil {
			continue
		}

		// 跳过标点符号
		if core.SafeType(child) == "," || core.SafeType(child) == "(" || core.SafeType(child) == ")" {
			continue
		}

		args = append(args, child)
	}

	return args
}

// extractLambdaCaptures 提取 Lambda 捕获的变量
func (d *DataRaceDetector) extractLambdaCaptures(ctx *core.AnalysisContext, lambdaNode *sitter.Node) []string {
	var captures []string

	// Lambda 结构: [&capture1, &capture2]() { body }
	// 需要检查捕获列表
	source := ctx.GetSourceText(lambdaNode)

	// 简化解析：查找 [&...] 模式
	idx := strings.Index(source, "[")
	if idx == -1 {
		return captures
	}

	endIdx := strings.Index(source[idx:], "]")
	if endIdx == -1 {
		return captures
	}

	captureList := source[idx+1 : idx+endIdx]

	// 解析捕获的变量
	// 按引用捕获: &var
	// 按值捕获: var
	parts := strings.Fields(captureList)
	for _, part := range parts {
		part = strings.TrimSuffix(part, ",")
		part = strings.TrimPrefix(part, "&")
		if part != "" && part != "=" && part != "&" {
			captures = append(captures, part)
		}
	}

	return captures
}

// estimateScopeEnd 估算作用域结束行
func (d *DataRaceDetector) estimateScopeEnd(ctx *core.AnalysisContext, declNode *sitter.Node) int {
	// 向上查找 compound_statement
	parent := declNode.Parent()
	for parent != nil {
		if core.SafeType(parent) == "compound_statement" {
			return int(parent.EndPoint().Row) + 1
		}
		parent = parent.Parent()
	}

	// 默认返回声明行 + 10（估算）
	return int(declNode.StartPoint().Row) + 11
}

// isAccessProtected 检查访问是否被保护
func (d *DataRaceDetector) isAccessProtected(access VariableAccess, protection SyncProtection) bool {
	// 检查函数是否匹配
	if access.Function != protection.Function {
		return false
	}

	// 检查行范围
	if access.Line >= protection.LineStart && access.Line <= protection.LineEnd {
		return true
	}

	return false
}

// haveSameProtection 检查两个访问是否有相同的保护锁
func (d *DataRaceDetector) haveSameProtection(a, b VariableAccess) bool {
	// 如果任一访问无保护，返回 false
	if !a.IsProtected || !b.IsProtected {
		return false
	}

	// 检查保护锁集合的交集
	for _, lockA := range a.GuardLocks {
		for _, lockB := range b.GuardLocks {
			if lockA == lockB {
				return true
			}
		}
	}

	return false
}

// contains 检查字符串是否包含子字符串
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findInString(s, substr)))
}

// findInString 在字符串中查找子字符串
func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
