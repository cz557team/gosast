package detectors

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// LockOpType 锁操作类型
type LockOpType int

const (
	LockOpUnknown       LockOpType = iota
	LockOpAcquire                  // pthread_mutex_lock
	LockOpRelease                  // pthread_mutex_unlock
	LockOpTryLock                  // pthread_mutex_trylock
	LockOpInit                     // pthread_mutex_init
	LockOpDestroy                  // pthread_mutex_destroy
	LockOpRdLock                   // pthread_rwlock_rdlock
	LockOpWrLock                   // pthread_rwlock_wrlock
	LockOpRdUnlock                 // pthread_rwlock_unlock
	LockOpCppAcquire               // std::mutex::lock()
	LockOpCppRelease               // std::mutex::unlock()
	LockOpCppGuard                 // std::lock_guard, std::unique_lock (acquire + auto release)
	LockOpCppScopedLock            // std::scoped_lock (atomic multi-lock)
)

// String 返回操作类型的字符串表示
func (t LockOpType) String() string {
	switch t {
	case LockOpAcquire:
		return "lock"
	case LockOpRelease:
		return "unlock"
	case LockOpTryLock:
		return "trylock"
	case LockOpInit:
		return "init"
	case LockOpDestroy:
		return "destroy"
	case LockOpRdLock:
		return "rdlock"
	case LockOpWrLock:
		return "wrlock"
	case LockOpRdUnlock:
		return "rdunlock"
	case LockOpCppAcquire:
		return "cpp_lock"
	case LockOpCppRelease:
		return "cpp_unlock"
	case LockOpCppGuard:
		return "cpp_guard"
	case LockOpCppScopedLock:
		return "cpp_scoped"
	default:
		return "unknown"
	}
}

// LockOperation 锁操作记录
type LockOperation struct {
	LockVar  string       // 锁变量名
	OpType   LockOpType   // 操作类型
	Function string       // 所在函数
	Line     int          // 行号
	Node     *sitter.Node // AST节点
}

// LockNode 锁图节点
type LockNode struct {
	Name        string          // 锁变量名
	Operations  []LockOperation // 所有锁操作
	CallSites   []string        // 使用位置
	IsInit      bool            // 是否已初始化
	IsRecursive bool            // 是否为递归锁
}

// LockEdge 锁图边（有向）
type LockEdge struct {
	From     string   // 源锁
	To       string   // 目标锁
	Weight   int      // 权重（出现次数）
	Function string   // 发生位置
	Line     int      // 行号
	Path     []string // 锁获取路径
}

// LockDependencyGraph 锁依赖图
type LockDependencyGraph struct {
	Nodes map[string]*LockNode // 锁节点
	Edges []LockEdge           // 锁边（有向）
}

// NewLockDependencyGraph 创建锁依赖图
func NewLockDependencyGraph() *LockDependencyGraph {
	return &LockDependencyGraph{
		Nodes: make(map[string]*LockNode),
		Edges: make([]LockEdge, 0),
	}
}

// AddNode 添加节点
func (g *LockDependencyGraph) AddNode(name string) *LockNode {
	if g.Nodes[name] == nil {
		g.Nodes[name] = &LockNode{
			Name:       name,
			Operations: make([]LockOperation, 0),
			CallSites:  make([]string, 0),
		}
	}
	return g.Nodes[name]
}

// AddEdge 添加边
func (g *LockDependencyGraph) AddEdge(from, to string, function string, line int) {
	// 检查边是否已存在
	for i, edge := range g.Edges {
		if edge.From == from && edge.To == to {
			g.Edges[i].Weight++
			return
		}
	}
	// 添加新边
	g.Edges = append(g.Edges, LockEdge{
		From:     from,
		To:       to,
		Weight:   1,
		Function: function,
		Line:     line,
	})
}

// GetOutgoingEdges 获取节点的出边
func (g *LockDependencyGraph) GetOutgoingEdges(node string) []LockEdge {
	var edges []LockEdge
	for _, edge := range g.Edges {
		if edge.From == node {
			edges = append(edges, edge)
		}
	}
	return edges
}

// DetectCycles 使用DFS检测图中的环
func (g *LockDependencyGraph) DetectCycles() [][]string {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	var cycles [][]string

	for node := range g.Nodes {
		if !visited[node] {
			g.dfsVisit(node, visited, recStack, []string{}, &cycles)
		}
	}
	return cycles
}

// dfsVisit DFS访问辅助函数
func (g *LockDependencyGraph) dfsVisit(node string, visited, recStack map[string]bool, path []string, cycles *[][]string) {
	visited[node] = true
	recStack[node] = true
	path = append(path, node)

	// 访问所有邻接节点
	for _, edge := range g.GetOutgoingEdges(node) {
		next := edge.To
		if !visited[next] {
			g.dfsVisit(next, visited, recStack, path, cycles)
		} else if recStack[next] {
			// 找到环
			cycleStart := -1
			for i, p := range path {
				if p == next {
					cycleStart = i
					break
				}
			}
			if cycleStart >= 0 {
				cycle := append([]string{}, path[cycleStart:]...)
				cycle = append(cycle, next) // 闭合环
				*cycles = append(*cycles, cycle)
			}
		}
	}

	// 回溯
	recStack[node] = false
}

// DeadlockDetector 死锁检测器
type DeadlockDetector struct {
	*core.BaseDetector
	lockGraph        *LockDependencyGraph
	lockOps          []LockOperation // 按执行顺序排列的锁操作
	heldLocks        map[string]bool // 模拟执行时当前持有的锁
	lockStack        []string        // 锁持有栈（用于检测嵌套）
	initializedLocks map[string]bool // 已初始化的锁
	// 【新增】宏展开检测 - 跟踪锁操作的位置模式 (锁变量名 -> 行号集合)
	macroPatternTracker map[string]map[int]int // lockVar -> line -> fileCount
}

// NewDeadlockDetector 创建死锁检测器
func NewDeadlockDetector() *DeadlockDetector {
	return &DeadlockDetector{
		BaseDetector:        core.NewBaseDetector("Deadlock Detector", "Detects potential deadlocks using lock graph and cycle detection (CWE-362)"),
		lockGraph:           NewLockDependencyGraph(),
		lockOps:             make([]LockOperation, 0),
		heldLocks:           make(map[string]bool),
		lockStack:           make([]string, 0),
		initializedLocks:    make(map[string]bool),
		macroPatternTracker: make(map[string]map[int]int),
	}
}

// Run 运行检测器
func (d *DeadlockDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 【修复】每个文件开始时清空状态，避免跨文件污染
	d.lockGraph = NewLockDependencyGraph()
	d.lockOps = make([]LockOperation, 0)
	d.heldLocks = make(map[string]bool)
	d.lockStack = make([]string, 0)
	d.initializedLocks = make(map[string]bool)

	// 1. 收集所有锁操作
	d.collectLockOperations(ctx)

	// 2. 收集锁初始化信息
	d.collectLockInitializations(ctx)

	// 3. 构建锁依赖图
	d.buildLockGraph(ctx)

	// 4. 检测环（潜在死锁）
	cycles := d.lockGraph.DetectCycles()

	for _, cycle := range cycles {
		vuln := d.reportDeadlockCycle(ctx, cycle)
		if vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	// 5. 检测锁配对问题
	d.checkLockPairing(ctx, &vulns)

	// 6. 检测未初始化的锁使用
	d.checkUninitializedLocks(ctx, &vulns)

	// 7. 检测递归锁问题
	d.checkRecursiveLockIssues(ctx, &vulns)

	return vulns, nil
}

// collectLockOperations 收集所有锁操作
func (d *DeadlockDetector) collectLockOperations(ctx *core.AnalysisContext) {
	// 查找所有函数调用
	callQuery := `(call_expression) @call`
	matches, err := ctx.Query(callQuery)
	if err != nil {
		return
	}

	for _, match := range matches {
		callExpr := match.Node
		if core.SafeChildCount(callExpr) < 2 {
			continue
		}

		// 提取函数名
		funcNode := core.SafeChild(callExpr, 0)
		if funcNode == nil {
			continue
		}

		var funcName string
		var opType LockOpType
		var lockVar string

		// 处理 C++ field_expression (m1.lock(), m1.unlock())
		if core.SafeType(funcNode) == "field_expression" {
			lockVar, opType = d.extractCppFieldLock(ctx, funcNode)
			if opType == LockOpUnknown {
				continue
			}
			funcName = "std::mutex"
		} else if core.SafeType(funcNode) == "identifier" {
			// 处理 C pthread 函数调用
			funcName = strings.TrimSpace(ctx.GetSourceText(funcNode))
			opType = d.getLockOpType(funcName)
			if opType == LockOpUnknown {
				continue
			}
			// 提取锁变量
			lockVar = d.extractLockVariable(ctx, callExpr)
			if lockVar == "" {
				continue
			}
		} else {
			continue
		}

		// 获取所在函数
		parentFunc := d.findParentFunction(ctx, callExpr)
		funcNameStr := ""
		if parentFunc != nil {
			funcNameStr = d.extractFunctionName(ctx, parentFunc)
		}

		line := int(callExpr.StartPoint().Row) + 1

		op := LockOperation{
			LockVar:  lockVar,
			OpType:   opType,
			Function: funcNameStr,
			Line:     line,
			Node:     callExpr,
		}
		d.lockOps = append(d.lockOps, op)

		// 添加到图的节点
		node := d.lockGraph.AddNode(lockVar)
		node.Operations = append(node.Operations, op)
		if funcNameStr != "" {
			node.CallSites = append(node.CallSites, funcNameStr)
		}
	}

	// 收集 C++ RAII 锁 (std::lock_guard, std::unique_lock, std::scoped_lock)
	d.collectCppLockGuards(ctx)

	// 【新增】收集宏展开模式 - 用于检测跨文件的重复位置模式
	d.collectMacroPatterns(ctx)
}

// collectLockInitializations 收集锁初始化信息
func (d *DeadlockDetector) collectLockInitializations(ctx *core.AnalysisContext) {
	// 查找 pthread_mutex_init 调用
	for _, op := range d.lockOps {
		if op.OpType == LockOpInit {
			d.initializedLocks[op.LockVar] = true
			if node := d.lockGraph.Nodes[op.LockVar]; node != nil {
				node.IsInit = true

				// 检查是否设置了递归锁属性
				if d.isRecursiveLockInit(ctx, op.Node) {
					node.IsRecursive = true
				}
			}
		}
	}
}

// buildLockGraph 构建锁依赖图
func (d *DeadlockDetector) buildLockGraph(ctx *core.AnalysisContext) {
	// 按函数分组分析
	opsByFunc := d.groupOpsByFunction()

	// 分析每个函数中的锁操作
	for funcName, ops := range opsByFunc {
		d.analyzeFunctionLockPattern(ctx, funcName, ops)
	}
}

// groupOpsByFunction 按函数分组锁操作
func (d *DeadlockDetector) groupOpsByFunction() map[string][]LockOperation {
	opsByFunc := make(map[string][]LockOperation)
	for _, op := range d.lockOps {
		funcName := op.Function
		if funcName == "" {
			funcName = "<global>"
		}
		opsByFunc[funcName] = append(opsByFunc[funcName], op)
	}
	return opsByFunc
}

// analyzeFunctionLockPattern 分析函数中的锁模式
func (d *DeadlockDetector) analyzeFunctionLockPattern(ctx *core.AnalysisContext, funcName string, ops []LockOperation) {
	// 模拟执行，跟踪持有的锁
	localHeld := make(map[string]bool)
	localStack := make([]string, 0)

	for _, op := range ops {
		switch op.OpType {
		case LockOpAcquire, LockOpTryLock, LockOpRdLock, LockOpWrLock, LockOpCppAcquire:
			// 在获取新锁时，记录所有当前持有的锁到新锁的边
			for heldLock := range localHeld {
				d.lockGraph.AddEdge(heldLock, op.LockVar, funcName, op.Line)
			}
			localHeld[op.LockVar] = true
			localStack = append(localStack, op.LockVar)

		case LockOpRelease, LockOpRdUnlock, LockOpCppRelease:
			localHeld[op.LockVar] = false
			// 从栈中移除
			for i, lock := range localStack {
				if lock == op.LockVar {
					localStack = append(localStack[:i], localStack[i+1:]...)
					break
				}
			}

		case LockOpCppGuard, LockOpCppScopedLock:
			// RAII 锁 - 获取锁 (自动释放在作用域结束，这里我们只记录获取)
			for heldLock := range localHeld {
				d.lockGraph.AddEdge(heldLock, op.LockVar, funcName, op.Line)
			}
			localHeld[op.LockVar] = true
			localStack = append(localStack, op.LockVar)
		}
	}
}

// getLockOpType 获取锁操作类型
func (d *DeadlockDetector) getLockOpType(funcName string) LockOpType {
	lockFuncs := map[string]LockOpType{
		"pthread_mutex_lock":    LockOpAcquire,
		"pthread_mutex_unlock":  LockOpRelease,
		"pthread_mutex_trylock": LockOpTryLock,
		"pthread_mutex_init":    LockOpInit,
		"pthread_mutex_destroy": LockOpDestroy,
		"pthread_rwlock_rdlock": LockOpRdLock,
		"pthread_rwlock_wrlock": LockOpWrLock,
		"pthread_rwlock_unlock": LockOpRdUnlock,
	}

	if opType, ok := lockFuncs[funcName]; ok {
		return opType
	}
	return LockOpUnknown
}

// extractLockVariable 从函数调用中提取锁变量
func (d *DeadlockDetector) extractLockVariable(ctx *core.AnalysisContext, callExpr *sitter.Node) string {
	if core.SafeChildCount(callExpr) < 2 {
		return ""
	}

	// 获取参数列表
	argList := core.SafeChild(callExpr, 1)
	if argList == nil {
		return ""
	}

	// 第一个参数通常是锁变量
	for i := 0; i < int(core.SafeChildCount(argList)); i++ {
		arg := core.SafeChild(argList, i)
		if arg == nil {
			continue
		}

		// 跳过标点符号
		if core.SafeType(arg) == "," || core.SafeType(arg) == "(" || core.SafeType(arg) == ")" {
			continue
		}

		// 处理 pointer_expression (例如 &lockA)
		if core.SafeType(arg) == "pointer_expression" {
			for j := 0; j < int(core.SafeChildCount(arg)); j++ {
				child := core.SafeChild(arg, j)
				if core.SafeType(child) == "identifier" {
					return ctx.GetSourceText(child)
				}
			}
		}

		// 处理 address_expression
		if core.SafeType(arg) == "address_expression" {
			if core.SafeChildCount(arg) > 0 {
				inner := core.SafeChild(arg, 0)
				if core.SafeType(inner) == "identifier" {
					return ctx.GetSourceText(inner)
				}
			}
		}

		// 处理标识符
		if core.SafeType(arg) == "identifier" {
			return ctx.GetSourceText(arg)
		}

		// 只获取第一个有效参数
		break
	}

	return ""
}

// findParentFunction 查找包含节点的函数
func (d *DeadlockDetector) findParentFunction(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
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
func (d *DeadlockDetector) extractFunctionName(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
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

// isRecursiveLockInit 检查是否是递归锁初始化
func (d *DeadlockDetector) isRecursiveLockInit(ctx *core.AnalysisContext, initCall *sitter.Node) bool {
	// 简化检查：查看init调用附近是否有PTHREAD_MUTEX_RECURSIVE
	// 实际实现需要更复杂的数据流分析
	source := ctx.GetSourceText(initCall.Parent())
	return strings.Contains(source, "PTHREAD_MUTEX_RECURSIVE") ||
		strings.Contains(source, "pthread_mutexattr_settype")
}

// reportDeadlockCycle 报告死锁环
func (d *DeadlockDetector) reportDeadlockCycle(ctx *core.AnalysisContext, cycle []string) *core.DetectorVulnerability {
	if len(cycle) < 2 {
		return nil
	}

	// 找到相关边的信息
	var edgeInfo []string
	for _, edge := range d.lockGraph.Edges {
		// 检查边是否在环中
		for i := 0; i < len(cycle)-1; i++ {
			if edge.From == cycle[i] && edge.To == cycle[i+1] {
				edgeInfo = append(edgeInfo, fmt.Sprintf("%s() at line %d", edge.Function, edge.Line))
			}
		}
		// 检查闭环
		if edge.From == cycle[len(cycle)-1] && edge.To == cycle[0] {
			edgeInfo = append(edgeInfo, fmt.Sprintf("%s() at line %d", edge.Function, edge.Line))
		}
	}

	cycleStr := strings.Join(cycle, " -> ")
	message := fmt.Sprintf("Potential deadlock detected: Lock acquisition cycle %s. Different code paths acquire locks in different orders, which can lead to deadlock. Lock order should be consistent across all code paths.", cycleStr)

	if len(edgeInfo) > 0 {
		message += fmt.Sprintf(" Related locations: %v", edgeInfo)
	}

	// 查找环中的任意节点来获取位置
	var locationNode *sitter.Node
	for _, lockName := range cycle {
		if node := d.lockGraph.Nodes[lockName]; node != nil && len(node.Operations) > 0 {
			locationNode = node.Operations[0].Node
			break
		}
	}

	vuln := d.BaseDetector.CreateVulnerability(
		core.CWE362, // CWE-362: Race Condition (includes Deadlock)
		message,
		locationNode,
		core.ConfidenceHigh,
		core.SeverityCritical,
	)

	return &vuln
}

// collectMacroPatterns 收集宏展开模式（通用方法）
// 检测同一锁变量在多个文件的相同行号出现的模式 - 通常是宏展开
func (d *DeadlockDetector) collectMacroPatterns(ctx *core.AnalysisContext) {
	for _, op := range d.lockOps {
		// 初始化该锁变量的行号映射
		if d.macroPatternTracker[op.LockVar] == nil {
			d.macroPatternTracker[op.LockVar] = make(map[int]int)
		}
		// 记录该行号出现的次数
		d.macroPatternTracker[op.LockVar][op.Line]++
	}
}

// isLikelyMacroExpansion 检查锁操作是否可能来自宏展开（通用方法）
// 判断依据：
// 1. 同一锁变量名在多个文件的相同行号出现（宏展开特征）
// 2. 锁变量名包含常见宏模式（如 _mutex, _lock 后缀）
// 3. 出现在头文件中（宏展开更常见）
func (d *DeadlockDetector) isLikelyMacroExpansion(ctx *core.AnalysisContext, op LockOperation) bool {
	// 检查1: 同一锁变量在同一行号出现在多个文件（>=3个文件视为宏展开模式）
	if lineCounts, ok := d.macroPatternTracker[op.LockVar]; ok {
		if count := lineCounts[op.Line]; count >= 3 {
			return true
		}
	}

	// 检查2: 检查是否在头文件中且锁变量名包含常见模式
	filePath := ctx.Unit.FilePath
	isHeaderFile := strings.HasSuffix(filePath, ".h") ||
		strings.HasSuffix(filePath, ".hpp") ||
		strings.HasSuffix(filePath, ".hxx")

	if isHeaderFile {
		// 常见的宏展开锁变量名模式
		commonMacroPatterns := []string{
			"_mutex", "_lock", "_mtex", "global_", "static_",
			"guard_", "protect_", "sync_", "thread_",
		}
		lowerName := strings.ToLower(op.LockVar)
		for _, pattern := range commonMacroPatterns {
			if strings.Contains(lowerName, pattern) {
				return true
			}
		}
	}

	return false
}

// checkLockPairing 检查锁配对问题
func (d *DeadlockDetector) checkLockPairing(ctx *core.AnalysisContext, vulns *[]core.DetectorVulnerability) {
	// 【新增】过滤测试文件
	if d.shouldSkipFile(ctx.Unit.FilePath) {
		return
	}

	// 按函数分组检查
	opsByFunc := d.groupOpsByFunction()

	for funcName, ops := range opsByFunc {
		// 【新增】跳过调用者管理的锁函数
		if d.isFunctionManagedLock(funcName) {
			continue
		}

		lockState := make(map[string]int) // 锁 -> 持有计数

		for _, op := range ops {
			// 【新增】跳过测试相关的锁变量
			if d.isSafeLockVarName(op.LockVar) {
				continue
			}

			switch op.OpType {
			case LockOpAcquire, LockOpTryLock, LockOpRdLock, LockOpWrLock, LockOpCppAcquire:
				lockState[op.LockVar]++

			case LockOpRelease, LockOpRdUnlock, LockOpCppRelease:
				if lockState[op.LockVar] == 0 {
					// 【新增】过滤宏展开相关的误报
					if d.isLikelyMacroExpansion(ctx, op) {
						continue
					}
					// 释放未持有的锁
					message := fmt.Sprintf("Releasing lock '%s' that was not acquired in function '%s' at line %d. This may indicate a lock pairing error or incorrect control flow.", op.LockVar, funcName, op.Line)
					vuln := d.BaseDetector.CreateVulnerability(
						core.CWE667, // CWE-667: Improper Locking
						message,
						op.Node,
						core.ConfidenceHigh,
						core.SeverityHigh,
					)
					*vulns = append(*vulns, vuln)
				}
				lockState[op.LockVar]--
			}
		}

		// 检查未释放的锁（不包括 RAII 锁，因为它们会自动释放）
		// 改进：提高阈值，减少误报
		for lock, count := range lockState {
			// 只有当锁持有数量 >= 3 时才报告（减少因路径敏感导致的误报）
			if count >= 3 {
				// 跳过测试相关的锁变量
				if d.isSafeLockVarName(lock) {
					continue
				}

				// 找到最后一次获取该锁的位置
				var lastLockOp LockOperation
				var isRaiiLock bool
				for _, op := range ops {
					if op.LockVar == lock && (op.OpType == LockOpAcquire || op.OpType == LockOpTryLock || op.OpType == LockOpCppAcquire) {
						lastLockOp = op
					}
					// 检查是否是 RAII 锁（会自动释放）
					if op.LockVar == lock && (op.OpType == LockOpCppGuard || op.OpType == LockOpCppScopedLock) {
						isRaiiLock = true
					}
				}

				// RAII 锁不需要检查未释放
				if isRaiiLock {
					continue
				}

				// 过滤宏展开相关的误报
				if d.isLikelyMacroExpansion(ctx, lastLockOp) {
					continue
				}

				message := fmt.Sprintf("Lock '%s' acquired %d times in function '%s' but never released (missing unlock). This can lead to deadlock.", lock, count, funcName)
				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE776, // CWE-776: Missing Release of Resource
					message,
					lastLockOp.Node, // 使用最后一次lock操作作为位置
					core.ConfidenceMedium,
					core.SeverityHigh,
				)
				*vulns = append(*vulns, vuln)
			}
		}
	}
}

// checkUninitializedLocks 检查未初始化的锁使用（改进版）
func (d *DeadlockDetector) checkUninitializedLocks(ctx *core.AnalysisContext, vulns *[]core.DetectorVulnerability) {
	// 过滤测试文件
	if d.shouldSkipFile(ctx.Unit.FilePath) {
		return
	}

	for _, op := range d.lockOps {
		// 跳过测试相关的锁变量
		if d.isSafeLockVarName(op.LockVar) {
			continue
		}

		if (op.OpType == LockOpAcquire || op.OpType == LockOpTryLock) && !d.initializedLocks[op.LockVar] {
			// 检查是否是全局变量（静态初始化）
			if !d.isPossiblyStaticInitialized(op.LockVar) {
				// 新增：检查是否可能是通过函数初始化的锁（跨函数初始化）
				// 例如：mutex_p = get_mutex(); 这种模式
				if d.isLikelyFunctionInitialized(op.LockVar) {
					continue
				}

				message := fmt.Sprintf("Using lock '%s' without proper initialization at line %d. Using an uninitialized mutex can lead to undefined behavior and potential deadlocks.", op.LockVar, op.Line)
				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE667, // CWE-667: Improper Locking
					message,
					op.Node,
					core.ConfidenceMedium,
					core.SeverityMedium,
				)
				*vulns = append(*vulns, vuln)
			}
		}
	}
}

// isPossiblyStaticInitialized 检查是否可能是静态初始化的（改进版）
func (d *DeadlockDetector) isPossiblyStaticInitialized(lockVar string) bool {
	lowerVar := strings.ToLower(lockVar)

	// 1. 检查变量名模式
	staticPatterns := []string{"static_", "global_", "g_", "_lock", "_mutex"}
	for _, pattern := range staticPatterns {
		if strings.Contains(lowerVar, pattern) {
			return true
		}
	}

	// 2. 检查是否是pthread静态初始化宏（编程语言通用symbol）
	// PTHREAD_MUTEX_INITIALIZER, PTHREAD_RWLOCK_INITIALIZER等
	pthreadStaticMacros := []string{
		"pthread_mutex_initializer",
		"pthread_recursive_mutex_initializer",
		"pthread_adaptive_mutex_initializer",
		"pthread_rwlock_initializer",
		"pthread_cond_initializer",
	}
	for _, macro := range pthreadStaticMacros {
		if strings.Contains(lowerVar, macro) {
			return true
		}
	}

	// 3. 检查常见的全局锁模式（大写、下划线分隔）
	// 例如: GLOBAL_LOCK, MUTEX_A, LOCK_B
	if strings.ToUpper(lockVar) == lockVar && (strings.Contains(lockVar, "_LOCK") || strings.Contains(lockVar, "_MUTEX") || strings.Contains(lockVar, "LOCK_")) {
		return true
	}

	return false
}

// isLikelyFunctionInitialized 检查是否可能是通过函数初始化的锁（通用编程模式）
// 例如：mutex_p = get_mutex(); 其中_p后缀通常表示pointer
func (d *DeadlockDetector) isLikelyFunctionInitialized(lockVar string) bool {
	lowerVar := strings.ToLower(lockVar)

	// 1. 指针变量模式（_p后缀）- 通常来自函数返回值
	if strings.HasSuffix(lowerVar, "_p") {
		return true
	}

	// 2. 通用指针模式
	if strings.HasSuffix(lowerVar, "_ptr") || strings.HasSuffix(lowerVar, "ptr") {
		return true
	}

	// 3. 参数/局部变量模式（通常是函数参数传入）
	paramPatterns := []string{"ctx_", "arg_", "param_"}
	for _, pattern := range paramPatterns {
		if strings.HasPrefix(lowerVar, pattern) {
			return true
		}
	}

	// 4. 常见的获取模式（get, fetch, acquire等）
	getPatterns := []string{"get_", "fetch_", "acquired_", "returned_"}
	for _, pattern := range getPatterns {
		if strings.Contains(lowerVar, pattern) {
			return true
		}
	}

	return false
}

// ============================================================================
// 通用误报过滤函数（参考 NULL pointer 检测器改进）
// ============================================================================

// shouldSkipFile 检查是否应该跳过该文件（通用模式）
func (d *DeadlockDetector) shouldSkipFile(filePath string) bool {
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
func (d *DeadlockDetector) extractRelativePath(filePath string) string {
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

// isSafeLockVarName 检查锁变量名是否是安全模式（通用）
func (d *DeadlockDetector) isSafeLockVarName(lockVar string) bool {
	if lockVar == "" {
		return false
	}

	lowerName := strings.ToLower(lockVar)

	// 1. 测试相关变量名
	testPatterns := []string{
		"test", "mock", "fake", "dummy", "stub",
		"temp", "tmp", "temporary", "example",
		"sample", "demo", "fixture",
	}
	for _, pattern := range testPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	// 2. 保护锁（这些通常用于保护测试代码）
	guardPatterns := []string{
		"guard_", "guardtest", "testguard",
	}
	for _, pattern := range guardPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	// 3. 循环中的临时锁（loop_ 开头或带数字）
	if strings.HasPrefix(lowerName, "lock_") && len(lockVar) > 6 {
		// lock_1, lock_2, lock_xxx
		suffix := lockVar[5:]
		if suffix[0] >= '0' && suffix[0] <= '9' {
			return true
		}
	}

	return false
}

// isFunctionManagedLock 检查是否是调用者管理的锁模式（通用）
// 有些函数只获取锁，释放由调用者负责（如 pthread_cleanup_push 的清理函数）
func (d *DeadlockDetector) isFunctionManagedLock(funcName string) bool {
	if funcName == "" {
		return false
	}

	lowerName := strings.ToLower(funcName)

	// 1. 锁管理包装函数（通用编程模式）
	// 这些函数内部执行锁操作，但由调用者负责配对
	wrapperPatterns := []string{
		"mutex_lock", "mutex_unlock",
		"rwlock_rdlock", "rwlock_wrlock", "rwlock_unlock",
		"thread_lock", "thread_unlock",
		"crypto_lock", "crypto_unlock",
		"sync_lock", "sync_unlock",
	}
	for _, pattern := range wrapperPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	// 2. 清理/处理函数（通常在异常/退出时调用）
	cleanupPatterns := []string{
		"cleanup", "clean", "finalize", "fini",
		"release_", "unlock_", "free_",
		"handler", "callback", "on_",
		"signal_", "notify_",
	}
	for _, pattern := range cleanupPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	// 3. 常见的调用者管理锁函数
	managedPatterns := []string{
		"__lock", "__unlock", // 内部辅助函数
		"_helper", "_internal", "_impl",
	}
	for _, pattern := range managedPatterns {
		if strings.HasSuffix(lowerName, pattern) {
			return true
		}
	}

	// 4. 析构/清理函数
	destructorPatterns := []string{
		"~", "destroy", "dispose", "close",
		"shutdown", "teardown",
	}
	for _, pattern := range destructorPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// checkRecursiveLockIssues 检查递归锁问题
func (d *DeadlockDetector) checkRecursiveLockIssues(ctx *core.AnalysisContext, vulns *[]core.DetectorVulnerability) {
	// 【新增】过滤测试文件
	if d.shouldSkipFile(ctx.Unit.FilePath) {
		return
	}

	// 检查在递归函数中使用非递归锁
	opsByFunc := d.groupOpsByFunction()

	for funcName, ops := range opsByFunc {
		// 检查函数是否递归
		if !d.isRecursiveFunction(ctx, funcName, ops) {
			continue
		}

		// 检查该函数中使用的锁
		usedLocks := make(map[string]bool)
		for _, op := range ops {
			// 【新增】跳过测试相关的锁变量
			if d.isSafeLockVarName(op.LockVar) {
				continue
			}

			if op.OpType == LockOpAcquire || op.OpType == LockOpTryLock || op.OpType == LockOpCppAcquire || op.OpType == LockOpCppGuard {
				usedLocks[op.LockVar] = true
			}
		}

		// 检查使用的锁是否是递归锁
		for lockName := range usedLocks {
			// 【新增】跳过测试相关的锁变量
			if d.isSafeLockVarName(lockName) {
				continue
			}

			if node := d.lockGraph.Nodes[lockName]; node != nil && !node.IsRecursive && !d.initializedLocks[lockName] {
				message := fmt.Sprintf("Function '%s' is recursive and uses non-recursive lock '%s'. This can cause deadlock when the function calls itself while holding the lock. Use pthread_mutexattr_settype with PTHREAD_MUTEX_RECURSIVE to initialize the mutex.", funcName, lockName)
				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE362, // CWE-362: Race Condition (includes Deadlock)
					message,
					ops[0].Node,
					core.ConfidenceHigh,
					core.SeverityHigh,
				)
				*vulns = append(*vulns, vuln)
			}
		}
	}
}

// isRecursiveFunction 检查函数是否递归
func (d *DeadlockDetector) isRecursiveFunction(ctx *core.AnalysisContext, funcName string, ops []LockOperation) bool {
	// 简化检查：如果在函数内部调用了自己
	for _, op := range ops {
		if op.Node != nil {
			source := ctx.GetSourceText(op.Node.Parent())
			if strings.Contains(source, funcName+"(") {
				return true
			}
		}
	}

	// 检查函数名模式
	recursivePatterns := []string{"recursive", "recurse", "traverse", "walk", "dfs", "bfs"}
	lowerName := strings.ToLower(funcName)
	for _, pattern := range recursivePatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// extractCppFieldLock 从 C++ field_expression 提取锁操作
// 例如: m1.lock() -> lockVar="m1", opType=LockOpCppAcquire
func (d *DeadlockDetector) extractCppFieldLock(ctx *core.AnalysisContext, fieldExpr *sitter.Node) (string, LockOpType) {
	if core.SafeChildCount(fieldExpr) < 3 {
		return "", LockOpUnknown
	}

	// field_expression 结构:
	// [0] identifier (m1)
	// [1] . (operator)
	// [2] field_identifier (lock/unlock)

	// 提取锁变量 (例如 m1)
	objNode := core.SafeChild(fieldExpr, 0)
	if objNode == nil || core.SafeType(objNode) != "identifier" {
		return "", LockOpUnknown
	}
	lockVar := ctx.GetSourceText(objNode)

	// 提取方法名 (例如 lock/unlock)
	methodNode := core.SafeChild(fieldExpr, 2)
	if methodNode == nil || core.SafeType(methodNode) != "field_identifier" {
		return "", LockOpUnknown
	}
	methodName := ctx.GetSourceText(methodNode)

	// 根据方法名确定操作类型
	switch methodName {
	case "lock":
		return lockVar, LockOpCppAcquire
	case "unlock":
		return lockVar, LockOpCppRelease
	case "try_lock":
		return lockVar, LockOpTryLock
	default:
		return "", LockOpUnknown
	}
}

// collectCppLockGuards 收集 C++ RAII 锁 (std::lock_guard, std::unique_lock, std::scoped_lock)
func (d *DeadlockDetector) collectCppLockGuards(ctx *core.AnalysisContext) {
	// 查找所有声明
	declQuery := `(declaration) @decl`
	matches, err := ctx.Query(declQuery)
	if err != nil {
		return
	}

	for _, match := range matches {
		declNode := match.Node

		// 获取声明的源文本
		declText := ctx.GetSourceText(declNode)

		// 检查是否是锁相关的声明
		isLockGuard := strings.Contains(declText, "lock_guard") || strings.Contains(declText, "unique_lock")
		isScopedLock := strings.Contains(declText, "scoped_lock")

		if !isLockGuard && !isScopedLock {
			continue
		}

		// 查找 function_declarator 子节点
		var funcDeclarator *sitter.Node
		for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
			child := core.SafeChild(declNode, i)
			if child != nil && core.SafeType(child) == "function_declarator" {
				funcDeclarator = child
				break
			}
		}

		if funcDeclarator == nil {
			continue
		}

		// 获取所在函数
		parentFunc := d.findParentFunction(ctx, declNode)
		funcNameStr := ""
		if parentFunc != nil {
			funcNameStr = d.extractFunctionName(ctx, parentFunc)
		}

		line := int(declNode.StartPoint().Row) + 1

		// 提取锁变量
		lockVars := d.extractLockVarsFromFunctionDeclarator(ctx, funcDeclarator)
		if len(lockVars) == 0 {
			continue
		}

		// 根据类型创建锁操作
		if isScopedLock {
			// std::scoped_lock - 同时获取多个锁
			opType := LockOpCppScopedLock

			// 为每个锁创建操作（scoped_lock 同时获取多个锁）
			for _, lockVar := range lockVars {
				op := LockOperation{
					LockVar:  lockVar,
					OpType:   opType,
					Function: funcNameStr,
					Line:     line,
					Node:     declNode,
				}
				d.lockOps = append(d.lockOps, op)

				node := d.lockGraph.AddNode(lockVar)
				node.Operations = append(node.Operations, op)
				if funcNameStr != "" {
					node.CallSites = append(node.CallSites, funcNameStr)
				}
			}
		} else {
			// std::lock_guard, std::unique_lock - 获取单个锁
			opType := LockOpCppGuard

			for _, lockVar := range lockVars {
				op := LockOperation{
					LockVar:  lockVar,
					OpType:   opType,
					Function: funcNameStr,
					Line:     line,
					Node:     declNode,
				}
				d.lockOps = append(d.lockOps, op)

				node := d.lockGraph.AddNode(lockVar)
				node.Operations = append(node.Operations, op)
				if funcNameStr != "" {
					node.CallSites = append(node.CallSites, funcNameStr)
				}
			}
		}
	}
}

// extractLockVarsFromFunctionDeclarator 从 function_declarator 提取锁变量
// 例如: lg(m1) -> ["m1"], sl(m1, m2) -> ["m1", "m2"]
func (d *DeadlockDetector) extractLockVarsFromFunctionDeclarator(ctx *core.AnalysisContext, funcDecl *sitter.Node) []string {
	var lockVars []string

	// C++ 标签类型，不是锁变量
	tagTypes := map[string]bool{
		"std::adopt_lock":  true,
		"adopt_lock":       true,
		"std::defer_lock":  true,
		"defer_lock":       true,
		"std::try_to_lock": true,
		"try_to_lock":      true,
	}

	// 查找 parameter_list
	for i := 0; i < int(core.SafeChildCount(funcDecl)); i++ {
		child := core.SafeChild(funcDecl, i)
		if child == nil {
			continue
		}

		if core.SafeType(child) == "parameter_list" {
			// 遍历参数列表
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				param := core.SafeChild(child, j)
				if param == nil {
					continue
				}

				// 跳过标点符号
				if core.SafeType(param) == "," || core.SafeType(param) == "(" || core.SafeType(param) == ")" {
					continue
				}

				var lockVar string

				// parameter_declaration - 获取其源文本作为锁变量名
				if core.SafeType(param) == "parameter_declaration" {
					lockVar = ctx.GetSourceText(param)
					// 清理可能的空格
					lockVar = strings.TrimSpace(lockVar)
				} else if core.SafeType(param) == "identifier" {
					// 直接是 identifier
					lockVar = ctx.GetSourceText(param)
				}

				// 过滤标签类型
				if lockVar != "" && !tagTypes[lockVar] {
					lockVars = append(lockVars, lockVar)
				}
			}
			break
		}
	}

	return lockVars
}
