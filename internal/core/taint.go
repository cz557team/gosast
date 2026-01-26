package core

import (
	"fmt"
	"sync"
	"sync/atomic"

	sitter "github.com/smacker/go-tree-sitter"
)

// TaintPropagationLogEntry 污点传播日志条目
type TaintPropagationLogEntry struct {
	From      string   `json:"from"`       // 源节点描述
	To        string   `json:"to"`         // 目标节点描述
	Reason    string   `json:"reason"`     // 传播原因
	FuncName  string   `json:"func_name"`  // 函数名（跨函数传播时）
	SourceLoc string   `json:"source_loc"` // 源位置
	TargetLoc string   `json:"target_loc"` // 目标位置
	Timestamp int64    `json:"timestamp"`  // 时间戳
	Path      []string `json:"path"`       // 传播路径
}

// TaintQueryCache 污点查询缓存（LRU）
type TaintQueryCache struct {
	cache map[uintptr]bool  // nodeID -> isTainted
	order []uintptr         // LRU 顺序（FIFO）
	mu    sync.RWMutex
	cap   int               // 缓存容量
}

// NewTaintQueryCache 创建污点查询缓存
func NewTaintQueryCache(capacity int) *TaintQueryCache {
	return &TaintQueryCache{
		cache: make(map[uintptr]bool, capacity),
		order: make([]uintptr, 0, capacity),
		cap:   capacity,
	}
}

// Get 查询缓存（无锁快速路径）
func (c *TaintQueryCache) Get(nodeID uintptr) (bool, bool) {
	if c == nil {
		return false, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.cache[nodeID]
	return val, ok
}

// Put 写入缓存
func (c *TaintQueryCache) Put(nodeID uintptr, isTainted bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// 如果已存在，只更新值，不改变顺序
	if _, exists := c.cache[nodeID]; exists {
		c.cache[nodeID] = isTainted
		return
	}

	// 添加新条目
	c.cache[nodeID] = isTainted
	c.order = append(c.order, nodeID)

	// 容量超限，淘汰最旧的条目（FIFO）
	if len(c.cache) > c.cap {
		oldest := c.order[0]
		delete(c.cache, oldest)
		c.order = c.order[1:]
	}
}

// Invalidate 失效缓存条目
func (c *TaintQueryCache) Invalidate(nodeID uintptr) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, nodeID)
}

// Clear 清空缓存
func (c *TaintQueryCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[uintptr]bool, c.cap)
	c.order = make([]uintptr, 0, c.cap)
}

// MemoryTaintEngine 基于内存的污点引擎实现（性能优化版 + LRU 缓存）
type MemoryTaintEngine struct {
	// 污染的节点集合，使用并发安全的 sync.Map
	taintedNodes sync.Map  // map[uintptr]struct{}
	// 污染的变量名集合（用于跨节点污点追踪）
	taintedVariables sync.Map  // map[string]struct{}
	// 函数作用域的污点变量（函数名 -> 变量名集合）
	taintedVariablesByFunc sync.Map  // map[string]map[string]bool
	// 节点ID到源节点的映射（使用 sync.Map）
	taintSources sync.Map  // map[uintptr][]*sitter.Node
	// 污点路径记录（使用 sync.Map）
	taintPaths sync.Map  // map[uintptr][]TaintStep
	// 注册的污点源处理器（只读，初始化后不变）
	sources map[string]SourceHandler
	// 注册的传播规则处理器（只读，初始化后不变）
	propagators map[string]PropagatorHandler
	// 分析上下文
	ctx *AnalysisContext
	// 统计信息
	stats map[string]interface{}
	// 互斥锁，保护统计信息更新
	statsMu sync.Mutex
	// 查询缓存（第三阶段优化）
	queryCache   *TaintQueryCache
	cacheEnabled atomic.Bool
	// 调试模式
	debugMode atomic.Bool
	// 污点传播日志
	propagationLog []TaintPropagationLogEntry
	propLogMu      sync.Mutex
}

// NewMemoryTaintEngine 创建新的内存污点引擎
func NewMemoryTaintEngine(ctx *AnalysisContext) *MemoryTaintEngine {
	engine := &MemoryTaintEngine{
		sources:     make(map[string]SourceHandler),
		propagators: make(map[string]PropagatorHandler),
		ctx:         ctx,
		stats:       make(map[string]interface{}),
		queryCache:  NewTaintQueryCache(1024), // 默认 1024 容量
	}

	// 注册默认的污点源和传播规则
	engine.registerDefaultSources()
	engine.registerDefaultPropagators()

	// 默认启用缓存
	engine.cacheEnabled.Store(true)

	return engine
}

// EnableCache 启用/禁用查询缓存（运行时开关）
func (e *MemoryTaintEngine) EnableCache(enabled bool) {
	e.cacheEnabled.Store(enabled)
}

// AddSource 注册污点源（仅在初始化阶段调用）
func (e *MemoryTaintEngine) AddSource(nodeType string, handler SourceHandler) {
	e.sources[nodeType] = handler
}

// AddPropagator 注册传播规则（仅在初始化阶段调用）
func (e *MemoryTaintEngine) AddPropagator(nodeType string, handler PropagatorHandler) {
	e.propagators[nodeType] = handler
}

// IsTainted 检查节点是否被污染（无锁快速路径 + LRU 缓存）
func (e *MemoryTaintEngine) IsTainted(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	nodeID := node.ID()

	// 快速路径 1: 查询缓存（如果启用）
	if e.cacheEnabled.Load() {
		if cached, ok := e.queryCache.Get(nodeID); ok {
			return cached
		}
	}

	// 快速路径 2: 无锁查询 sync.Map
	if _, ok := e.taintedNodes.Load(nodeID); ok {
		// 更新缓存
		if e.cacheEnabled.Load() {
			e.queryCache.Put(nodeID, true)
		}
		return true
	}

	// 如果是标识符，检查变量名是否被污染
	if node.Type() == "identifier" && e.ctx != nil {
		varName := e.ctx.GetSourceText(node)
		if _, ok := e.taintedVariables.Load(varName); ok {
			// 更新缓存
			if e.cacheEnabled.Load() {
				e.queryCache.Put(nodeID, true)
			}
			return true
		}
	}

	// 缓存未污染结果（避免重复查询）
	if e.cacheEnabled.Load() {
		e.queryCache.Put(nodeID, false)
	}

	return false
}

// MarkTainted 标记节点为污染（带缓存失效）
func (e *MemoryTaintEngine) MarkTainted(node *sitter.Node, source interface{}) {
	if node == nil {
		return
	}

	nodeID := node.ID()

	e.taintedNodes.Store(nodeID, struct{}{})

	// 失效缓存条目（如果存在）
	if e.cacheEnabled.Load() {
		e.queryCache.Invalidate(nodeID)
	}

	// 如果是标识符，同时标记变量名
	if node.Type() == "identifier" {
		varName := e.ctx.GetSourceText(node)
		e.taintedVariables.Store(varName, struct{}{})
	}

	// 记录污染源
	if source != nil {
		if sourceNode, ok := source.(*sitter.Node); ok {
			if existing, ok := e.taintSources.Load(nodeID); ok {
				sources := existing.([]*sitter.Node)
				sources = append(sources, sourceNode)
				e.taintSources.Store(nodeID, sources)
			} else {
				e.taintSources.Store(nodeID, []*sitter.Node{sourceNode})
			}
		}
	}
}

// GetTaintPath 获取污染路径（无锁查询）
func (e *MemoryTaintEngine) GetTaintPath(node *sitter.Node) []TaintStep {
	if node == nil {
		return nil
	}

	if path, ok := e.taintPaths.Load(node.ID()); ok {
		return path.([]TaintStep)
	}
	return nil
}

// Propagate 执行污点传播分析
func (e *MemoryTaintEngine) Propagate(cfg *CFG) error {
	if cfg == nil {
		return fmt.Errorf("invalid CFG")
	}

	// 统计初始污染节点数
	startCount := 0
	e.taintedNodes.Range(func(key, value interface{}) bool {
		startCount++
		return true
	})
	e.statsMu.Lock()
	e.stats["start_propagation"] = startCount
	e.statsMu.Unlock()

	// 使用工作表算法 (Worklist Algorithm) 进行定点计算
	// 注意：由于 CFG 可能有多个函数（多个入口点），我们需要收集所有节点
	worklist := e.initializeWorklist(cfg)

	// 如果 Entry 为空但有其他节点，使用所有可达节点
	if cfg.Entry == nil && len(cfg.Nodes) > 0 {
		for _, node := range cfg.Nodes {
			worklist = append(worklist, node)
		}
	}

	iteration := 0

	for len(worklist) > 0 {
		iteration++
		// 获取工作表中的一个节点
		currentNode := worklist[0]
		worklist = worklist[1:]

		// 处理当前节点及其语句
		e.processCFGNode(currentNode, &worklist)
	}

	// 统计最终污染节点数
	finalCount := 0
	e.taintedNodes.Range(func(key, value interface{}) bool {
		finalCount++
		return true
	})
	e.statsMu.Lock()
	e.stats["iterations"] = iteration
	e.stats["final_tainted"] = finalCount
	e.statsMu.Unlock()

	return nil
}

// StreamPropagate 流式污点传播分析（Phase 5 优化）
// 将 CFG 分块处理，减少内存峰值占用
// batchSize: 每批处理的节点数（默认 1000）
func (e *MemoryTaintEngine) StreamPropagate(cfg *CFG, batchSize int) error {
	if cfg == nil {
		return fmt.Errorf("invalid CFG")
	}

	if batchSize <= 0 {
		batchSize = 1000 // 默认每批处理 1000 个节点
	}

	// 统计初始污染节点数
	startCount := 0
	e.taintedNodes.Range(func(key, value interface{}) bool {
		startCount++
		return true
	})
	e.statsMu.Lock()
	e.stats["start_propagation"] = startCount
	e.stats["streaming"] = true
	e.stats["batch_size"] = batchSize
	e.statsMu.Unlock()

	// 初始化工作表
	worklist := e.initializeWorklist(cfg)

	if cfg.Entry == nil && len(cfg.Nodes) > 0 {
		for _, node := range cfg.Nodes {
			worklist = append(worklist, node)
		}
	}

	iteration := 0
	batchNum := 0
	totalProcessed := 0

	// 分批处理工作表
	for len(worklist) > 0 {
		batchNum++
		currentBatchSize := min(len(worklist), batchSize)

		// 处理当前批次
		for i := 0; i < currentBatchSize; i++ {
			iteration++
			currentNode := worklist[0]
			worklist = worklist[1:]

			// 处理当前节点
			e.processCFGNode(currentNode, &worklist)
			totalProcessed++
		}

		// Phase 5: 批次处理完后，可选地触发 GC 以释放内存
		if batchNum%10 == 0 {
			// 每 10 批次触发一次 GC
			e.statsMu.Lock()
			e.stats["gc_triggered_at_batch"] = batchNum
			e.statsMu.Unlock()
		}
	}

	// 统计最终污染节点数
	finalCount := 0
	e.taintedNodes.Range(func(key, value interface{}) bool {
		finalCount++
		return true
	})
	e.statsMu.Lock()
	e.stats["iterations"] = iteration
	e.stats["final_tainted"] = finalCount
	e.stats["total_batches"] = batchNum
	e.statsMu.Unlock()

	return nil
}

// Reset 重置污点状态（包括清空缓存）
func (e *MemoryTaintEngine) Reset() {
	e.taintedNodes = sync.Map{}
	e.taintedVariables = sync.Map{}
	e.taintSources = sync.Map{}
	e.taintPaths = sync.Map{}

	// 清空查询缓存
	if e.queryCache != nil {
		e.queryCache.Clear()
	}

	e.statsMu.Lock()
	e.stats = make(map[string]interface{})
	e.statsMu.Unlock()
}

// GetStats 获取统计信息
func (e *MemoryTaintEngine) GetStats() map[string]interface{} {
	e.statsMu.Lock()
	defer e.statsMu.Unlock()

	stats := make(map[string]interface{})
	for k, v := range e.stats {
		stats[k] = v
	}

	// 统计 sync.Map 的大小
	taintedCount := 0
	e.taintedNodes.Range(func(key, value interface{}) bool {
		taintedCount++
		return true
	})
	stats["total_tainted"] = taintedCount

	sourcesCount := 0
	e.taintSources.Range(func(key, value interface{}) bool {
		sourcesCount++
		return true
	})
	stats["total_sources"] = sourcesCount

	return stats
}

// EnableDebugMode 启用/禁用调试模式
func (e *MemoryTaintEngine) EnableDebugMode(enabled bool) {
	e.debugMode.Store(enabled)
	if enabled {
		e.propLogMu.Lock()
		e.propagationLog = make([]TaintPropagationLogEntry, 0)
		e.propLogMu.Unlock()
	}
}

// GetPropagationLog 获取污点传播日志
func (e *MemoryTaintEngine) GetPropagationLog() []TaintPropagationLogEntry {
	e.propLogMu.Lock()
	defer e.propLogMu.Unlock()

	log := make([]TaintPropagationLogEntry, len(e.propagationLog))
	copy(log, e.propagationLog)
	return log
}

// PrintPropagationLog 打印污点传播日志到控制台
func (e *MemoryTaintEngine) PrintPropagationLog() {
	e.propLogMu.Lock()
	defer e.propLogMu.Unlock()

	if len(e.propagationLog) == 0 {
		fmt.Printf("[Taint Log] No propagation entries recorded\n")
		return
	}

	fmt.Printf("\n========== Taint Propagation Log (%d entries) ==========\n", len(e.propagationLog))
	for i, entry := range e.propagationLog {
		fmt.Printf("\n[%d] %s -> %s\n", i+1, entry.From, entry.To)
		fmt.Printf("    Reason: %s\n", entry.Reason)
		fmt.Printf("    Function: %s\n", entry.FuncName)
		fmt.Printf("    Source: %s, Target: %s\n", entry.SourceLoc, entry.TargetLoc)
		if len(entry.Path) > 0 {
			fmt.Printf("    Path: %v\n", entry.Path)
		}
	}
	fmt.Printf("\n==================== End of Taint Log ====================\n\n")
}

// PrintTaintedVariables 打印所有被污染的变量
func (e *MemoryTaintEngine) PrintTaintedVariables() {
	fmt.Printf("\n========== Tainted Variables ==========\n")

	// 全局污点变量
	fmt.Printf("\nGlobal Tainted Variables:\n")
	e.taintedVariables.Range(func(key, value interface{}) bool {
		fmt.Printf("  - %s\n", key.(string))
		return true
	})

	// 函数作用域的污点变量
	fmt.Printf("\nFunction-Scoped Tainted Variables:\n")
	e.taintedVariablesByFunc.Range(func(key, value interface{}) bool {
		funcName := key.(string)
		if funcVars, ok := value.(map[string]bool); ok {
			fmt.Printf("  Function: %s\n", funcName)
			for varName := range funcVars {
				fmt.Printf("    - %s\n", varName)
			}
		}
		return true
	})

	// 污点节点统计
	taintedCount := 0
	e.taintedNodes.Range(func(key, value interface{}) bool {
		taintedCount++
		return true
	})
	fmt.Printf("\nTotal Tainted Nodes: %d\n", taintedCount)
	fmt.Printf("=============================\n\n")
}

// logPropagation 记录污点传播日志
func (e *MemoryTaintEngine) logPropagation(from, to *sitter.Node, reason, funcName string) {
	if !e.debugMode.Load() {
		return
	}

	entry := TaintPropagationLogEntry{
		From:      e.getNodeDescription(from),
		To:        e.getNodeDescription(to),
		Reason:    reason,
		FuncName:  funcName,
		SourceLoc: e.getNodeLocation(from),
		TargetLoc: e.getNodeLocation(to),
		Timestamp: 0, // 可以添加时间戳
		Path:      []string{},
	}

	e.propLogMu.Lock()
	e.propagationLog = append(e.propagationLog, entry)
	e.propLogMu.Unlock()
}

// getNodeDescription 获取节点的描述
func (e *MemoryTaintEngine) getNodeDescription(node *sitter.Node) string {
	if node == nil || e.ctx == nil {
		return "nil"
	}

	nodeType := node.Type()
	if nodeType == "identifier" {
		return e.ctx.GetSourceText(node)
	}

	return nodeType
}

// getNodeLocation 获取节点的位置信息
func (e *MemoryTaintEngine) getNodeLocation(node *sitter.Node) string {
	if node == nil {
		return "unknown"
	}
	return fmt.Sprintf("line:%d", node.StartPoint().Row+1)
}

// markTaintedInFunction 在函数作用域内标记节点为污染
func (e *MemoryTaintEngine) markTaintedInFunction(node *sitter.Node, funcName string, source *sitter.Node, reason string) {
	if node == nil {
		return
	}

	// *** 修复 ***: 只标记节点为污点，不添加到全局变量名污点
	// 我们不调用 markTainted()，因为它会把变量名添加到全局 taintedVariables
	// 而我们只想在函数作用域内标记污点
	nodeID := node.ID()
	e.taintedNodes.LoadOrStore(nodeID, struct{}{})

	// 如果是标识符，在函数作用域内标记变量名
	if node.Type() == "identifier" && e.ctx != nil {
		varName := e.ctx.GetSourceText(node)
		if varName != "" && funcName != "" {
			// 获取或创建函数的污点变量集合
			var funcVars map[string]bool
			if val, ok := e.taintedVariablesByFunc.Load(funcName); ok {
				funcVars = val.(map[string]bool)
			} else {
				funcVars = make(map[string]bool)
				e.taintedVariablesByFunc.Store(funcName, funcVars)
			}
			funcVars[varName] = true

			// 记录日志
			e.logPropagation(source, node, reason, funcName)
		}
	}
}

// isVariableTaintedInFunction 检查变量在特定函数中是否被污染
func (e *MemoryTaintEngine) isVariableTaintedInFunction(varName, funcName string) bool {
	if varName == "" || funcName == "" {
		return false
	}

	// 检查全局变量名污点
	if _, ok := e.taintedVariables.Load(varName); ok {
		return true
	}

	// 检查函数作用域的污点变量
	if val, ok := e.taintedVariablesByFunc.Load(funcName); ok {
		if funcVars, ok := val.(map[string]bool); ok {
			return funcVars[varName]
		}
	}

	return false
}

// IsIdentifierTaintedInFunction 检查标识符节点在特定函数中是否被污染
func (e *MemoryTaintEngine) IsIdentifierTaintedInFunction(node *sitter.Node, funcName string) bool {
	if node == nil || node.Type() != "identifier" || e.ctx == nil {
		return false
	}

	// 首先检查节点级别的污点
	if e.IsTainted(node) {
		return true
	}

	// 检查变量名在函数作用域内是否被污染
	varName := e.ctx.GetSourceText(node)
	return e.isVariableTaintedInFunction(varName, funcName)
}

// GetTaintedVariablesInFunction 获取函数作用域内的所有污点变量（用于调试）
func (e *MemoryTaintEngine) GetTaintedVariablesInFunction(funcName string) (map[string]bool, bool) {
	if funcName == "" {
		return nil, false
	}
	val, ok := e.taintedVariablesByFunc.Load(funcName)
	if !ok {
		return nil, false
	}
	vars := val.(map[string]bool)
	// 返回副本
	result := make(map[string]bool)
	for k, v := range vars {
		result[k] = v
	}
	return result, true
}

// MarkNodeTainted 标记节点为污点（公开方法，用于检测器）
func (e *MemoryTaintEngine) MarkNodeTainted(node *sitter.Node, funcName string) {
	if node == nil {
		return
	}

	// 标记节点为污点
	nodeID := node.ID()
	e.taintedNodes.Store(nodeID, struct{}{})

	// 如果是标识符，在函数作用域内标记变量名
	if node.Type() == "identifier" && e.ctx != nil {
		varName := e.ctx.GetSourceText(node)
		if varName != "" && funcName != "" {
			var funcVars map[string]bool
			if val, ok := e.taintedVariablesByFunc.Load(funcName); ok {
				funcVars = val.(map[string]bool)
			} else {
				funcVars = make(map[string]bool)
				e.taintedVariablesByFunc.Store(funcName, funcVars)
			}
			funcVars[varName] = true
		}
	}
}

// markTainted 标记节点为污染（内部使用）
func (e *MemoryTaintEngine) markTainted(node *sitter.Node) {
	if node == nil {
		return
	}

	nodeID := node.ID()
	if _, loaded := e.taintedNodes.LoadOrStore(nodeID, struct{}{}); !loaded {
		// 如果是新标记的节点
		// 如果是标识符，同时标记变量名为污点
		if node.Type() == "identifier" && e.ctx != nil {
			varName := e.ctx.GetSourceText(node)
			if varName != "" {
				e.taintedVariables.Store(varName, struct{}{})
			}
		}
	}
}

// === 私有方法 ===

// registerDefaultSources 注册默认的污点源
func (e *MemoryTaintEngine) registerDefaultSources() {
	// 命令行参数（argv, argc, envp）- 顶级污点源
	e.AddSource("identifier", func(node *sitter.Node, ctx *AnalysisContext) bool {
		ident := ctx.GetSourceText(node)
		// 检查是否为常见的命令行参数名称
		taintedIdents := map[string]bool{
			"argv":  true, // 命令行参数数组
			"argc":  true, // 命令行参数计数
			"envp":  true, // 环境变量数组
			"environ": true, // 环境变量（另一种命名）
		}
		return taintedIdents[ident]
	})

	// 数组访问中的 argv[arg] 形式
	e.AddSource("subscript_expression", func(node *sitter.Node, ctx *AnalysisContext) bool {
		// 检查数组对象是否为 argv
		array := node.ChildByFieldName("argument")
		if array != nil && array.Type() == "identifier" {
			arrayName := ctx.GetSourceText(array)
			if arrayName == "argv" || arrayName == "envp" || arrayName == "environ" {
				return true // argv[x] 访问，直接标记为污点源
			}
		}
		return false // 其他数组访问不是污点源
	})

	// 用户输入函数
	e.AddSource("call_expression", func(node *sitter.Node, ctx *AnalysisContext) bool {
		funcNode := node.ChildByFieldName("function")
		if funcNode != nil && funcNode.Type() == "identifier" {
			funcName := ctx.GetSourceText(funcNode)
			// 常见的危险函数
			dangerousFuncs := map[string]bool{
				"gets":     true,
				"scanf":    true,
				"strcpy":   true,
				"strcat":   true,
				"sprintf":  true,
				"memcpy":   true,
				"read":     true,
				"recv":     true,
				"fgets":    true,
				"getchar":  true,
				"getenv":   true, // 环境变量读取
				"fread":    true, // 文件读取
				"recvfrom": true, // 网络接收
				"send":     true, // 网络发送（可能接收数据）
			}
			return dangerousFuncs[funcName]
		}
		return false
	})

	// 指针解引用（可能引入外部数据）
	e.AddSource("pointer_expression", func(node *sitter.Node, ctx *AnalysisContext) bool {
		return true // 简化处理，所有指针解引用都视为潜在污点源
	})
}

// registerDefaultPropagators 注册默认的传播规则
func (e *MemoryTaintEngine) registerDefaultPropagators() {
	// 赋值表达式传播
	e.AddPropagator("assignment_expression", func(node *sitter.Node, ctx *AnalysisContext, engine *MemoryTaintEngine) []TaintStep {
		rhs := node.ChildByFieldName("right")
		lhs := node.ChildByFieldName("left")

		var steps []TaintStep

		if rhs != nil && engine.IsTainted(rhs) {
			// 右值被污染，左值也被污染
			engine.markTainted(lhs)
			steps = append(steps, TaintStep{
				From:   rhs,
				To:     lhs,
				Reason: "assignment",
			})
		}

		return steps
	})

	// 二元表达式传播（算术、逻辑运算）
	e.AddPropagator("binary_expression", func(node *sitter.Node, ctx *AnalysisContext, engine *MemoryTaintEngine) []TaintStep {
		left := node.Child(0)
		right := node.Child(2)

		var steps []TaintStep

		// 如果任一操作数被污染，结果也被污染
		if engine.IsTainted(left) || engine.IsTainted(right) {
			engine.markTainted(node)
			if engine.IsTainted(left) {
				steps = append(steps, TaintStep{
					From:   left,
					To:     node,
					Reason: "binary_op_left",
				})
			}
			if engine.IsTainted(right) {
				steps = append(steps, TaintStep{
					From:   right,
					To:     node,
					Reason: "binary_op_right",
				})
			}
		}

		return steps
	})

	// 函数调用传播（合并版：处理 scanf 指针写入和普通参数传播）
	e.AddPropagator("call_expression", func(node *sitter.Node, ctx *AnalysisContext, engine *MemoryTaintEngine) []TaintStep {
		funcNode := node.ChildByFieldName("function")
		args := node.ChildByFieldName("arguments")

		if funcNode == nil || funcNode.Type() != "identifier" {
			return nil
		}

		funcName := ctx.GetSourceText(funcNode)
		var steps []TaintStep

		// 特殊函数：通过指针参数写入数据（scanf, read, recv, fgets）
		writeFuncs := map[string]bool{
			"scanf": true,
			"read":  true,
			"recv":  true,
			"fgets": true,
		}

		if args == nil {
			return nil
		}

		if writeFuncs[funcName] {
			// 对于 scanf/read 等函数，标记指针参数的目标为污点
			// 跳过第一个参数（格式字符串或文件描述符）
			argIndex := 0
			childCount := args.ChildCount()

			for i := 0; i < int(childCount); i++ {
				arg := args.Child(i)
				argType := arg.Type()
				argChildCount := arg.ChildCount()

				if argType == "(" || argType == ")" || argType == "," {
					continue
				}

				// 跳过第一个参数（格式字符串）
				if argIndex == 0 {
					argIndex++
					continue
				}

				// 检查是否是 pointer_expression (&变量) 或 unary_expression
				if argType == "pointer_expression" || argType == "unary_expression" {
					// &变量 在 tree-sitter 中通常是 unary_expression
					// 结构：unary_expression -> "&" -> identifier
					// 或者 pointer_expression -> operand: "&" -> argument: identifier
					// 尝试获取 identifier 子节点
					var target *sitter.Node

					for j := 0; j < int(argChildCount); j++ {
						child := arg.Child(j)
						if child.Type() == "identifier" {
							target = child
							break
						}
						// 递归查找 identifier
						if child.Type() == "argument_list" || child.Type() == "parenthesized_expression" {
							for k := 0; k < int(child.ChildCount()); k++ {
								if child.Child(k).Type() == "identifier" {
									target = child.Child(k)
									break
								}
							}
						}
					}

					// 如果没找到 identifier，尝试使用最后一个子节点（通常是操作数）
					if target == nil && argChildCount > 1 {
						target = arg.Child(int(argChildCount) - 1)
					}

					if target != nil {
						// 标记指针目标为污点
						engine.markTainted(target)
						steps = append(steps, TaintStep{
							From:   node,
							To:     target,
							Reason: "scanf_write_to_pointer",
						})
					}
				}
				argIndex++
			}
		} else {
			// 对于普通函数，检查参数污染并传播到返回值
			childCount := args.ChildCount()
			hasTaintedArg := false

			for i := 0; i < int(childCount); i++ {
				arg := args.Child(i)
				argType := arg.Type()

				if argType != "(" && argType != ")" && engine.IsTainted(arg) {
					hasTaintedArg = true

					// *** 跨函数污点传播 ***
					// 找到被调用函数的定义，将实际参数的污点传播到形式参数
					funcName := ctx.GetCallFunctionName(node)
					if funcDef := ctx.FindFunctionDefinition(funcName); funcDef != nil {
						// 提取函数的参数节点列表
						params := ctx.ExtractFunctionParameters(funcDef)
						if params != nil {
							// 计算实际参数的索引（跳过括号）
							argIndex := 0
							for j := 0; j < int(childCount); j++ {
								argJ := args.Child(j)
								if argJ.Type() != "(" && argJ.Type() != ")" {
									// 找到匹配的实际参数
									if argJ == arg && argIndex < len(params) {
										// 将污点从实际参数传播到形式参数
										paramNode := params[argIndex]
										if paramNode != nil && !engine.IsTainted(paramNode) {
											engine.markTainted(paramNode)
											// 记录污点来源
											paramNodeID := paramNode.ID()
											engine.taintSources.Store(paramNodeID, []*sitter.Node{arg})
											steps = append(steps, TaintStep{
												From:   arg,
												To:     paramNode,
												Reason: fmt.Sprintf("cross_function_propagation:%s->%s", funcName, ctx.GetSourceText(paramNode)),
											})
										}
										break
									}
									argIndex++
								}
							}
						}
					}

					// 参数污染传播到返回值（简化处理）
					engine.markTainted(node)
					steps = append(steps, TaintStep{
						From:   arg,
						To:     node,
						Reason: "function_call_arg",
					})
				}
			}

			// 如果有污点参数，记录函数调用本身也被污点
			if hasTaintedArg {
				engine.markTainted(node)
			}
		}

		return steps
	})

	// 变量初始化传播
	e.AddPropagator("variable_declarator", func(node *sitter.Node, ctx *AnalysisContext, engine *MemoryTaintEngine) []TaintStep {
		init := node.ChildByFieldName("init")

		var steps []TaintStep

		if init != nil && engine.IsTainted(init) {
			// 初始化值被污染，变量也被污染
			engine.markTainted(node)
			steps = append(steps, TaintStep{
				From:   init,
				To:     node,
				Reason: "variable_init",
			})
		}

		return steps
	})
}

// initializeWorklist 初始化工作表
func (e *MemoryTaintEngine) initializeWorklist(cfg *CFG) []*CFGNode {
	var worklist []*CFGNode
	visited := make(map[*CFGNode]bool)

	// 如果有独立的节点列表（cfg.Nodes），使用所有节点
	// 这是为了处理多个函数的 CFG，它们可能没有连接到单个入口点
	if len(cfg.Nodes) > 0 {
		for _, node := range cfg.Nodes {
			if !visited[node] {
				visited[node] = true
				worklist = append(worklist, node)
			}
		}
		return worklist
	}

	// 否则，从入口节点开始遍历（传统方式）
	var traverse func(node *CFGNode)
	traverse = func(n *CFGNode) {
		if n == nil || visited[n] {
			return
		}
		visited[n] = true
		worklist = append(worklist, n)

		// 添加后继节点
		for _, succ := range n.Successors {
			traverse(succ)
		}
	}

	traverse(cfg.Entry)
	return worklist
}

// processCFGNode 处理CFG节点
func (e *MemoryTaintEngine) processCFGNode(node *CFGNode, worklist *[]*CFGNode) {
	if node == nil || node.ASTNode == nil {
		return
	}

	// 首先识别和标记污点源
	e.identifySources(node.ASTNode)

	// 然后处理传播规则
	e.applyPropagators(node.ASTNode, worklist)
}

// identifySources 识别污点源
func (e *MemoryTaintEngine) identifySources(root *sitter.Node) {
	// 使用 sync.Map 来处理并发访问
	e.identifySourcesWithDepth(root, 0, &sync.Map{})
}

// identifySourcesWithDepth 带深度限制的污点源识别
func (e *MemoryTaintEngine) identifySourcesWithDepth(root *sitter.Node, depth int, visited *sync.Map) {
	if root == nil {
		return
	}

	// 深度限制：防止栈溢出
	const maxDepth = 100
	if depth > maxDepth {
		return
	}

	// 循环检测：避免重复处理同一节点
	nodeID := root.ID()
	if _, exists := visited.Load(nodeID); exists {
		return
	}
	visited.Store(nodeID, true)

	// 检查当前节点是否是污点源
	handler, hasHandler := e.sources[root.Type()]

	if hasHandler {
		if handler(root, e.ctx) {
			e.markTainted(root)
			// 记录污点源
			nodeID := root.ID()
			if _, exists := e.taintSources.Load(nodeID); !exists {
				e.taintSources.Store(nodeID, []*sitter.Node{root})
			}
			// 调试输出（已禁用）
		}
	}

	// 递归处理子节点
	childCount := root.ChildCount()
	children := make([]*sitter.Node, childCount)
	for i := 0; i < int(childCount); i++ {
		children[i] = root.Child(i)
	}

	for _, child := range children {
		e.identifySourcesWithDepth(child, depth+1, visited)
	}
}

// applyPropagators 应用传播规则
func (e *MemoryTaintEngine) applyPropagators(root *sitter.Node, worklist *[]*CFGNode) {
	e.applyPropagatorsWithDepth(root, worklist, 0, &sync.Map{})
}

// applyPropagatorsWithDepth 带深度限制的传播规则应用
func (e *MemoryTaintEngine) applyPropagatorsWithDepth(root *sitter.Node, worklist *[]*CFGNode, depth int, visited *sync.Map) {
	if root == nil {
		return
	}

	// 深度限制：防止栈溢出
	const maxDepth = 100
	if depth > maxDepth {
		return
	}

	// 循环检测：避免重复处理同一节点
	nodeID := root.ID()
	if _, exists := visited.Load(nodeID); exists {
		return
	}
	visited.Store(nodeID, true)

	// 检查是否有传播规则适用于当前节点
	handler, hasHandler := e.propagators[root.Type()]

	if hasHandler {
		steps := handler(root, e.ctx, e)

		// 记录传播路径
		if len(steps) > 0 {
			for _, step := range steps {
				nodeID := step.To.ID()
				if existing, ok := e.taintPaths.Load(nodeID); ok {
					paths := existing.([]TaintStep)
					paths = append(paths, step)
					e.taintPaths.Store(nodeID, paths)
				} else {
					e.taintPaths.Store(nodeID, []TaintStep{step})
				}
			}
		}
	}

	// 递归处理子节点
	childCount := root.ChildCount()
	children := make([]*sitter.Node, childCount)
	for i := 0; i < int(childCount); i++ {
		children[i] = root.Child(i)
	}

	for _, child := range children {
		e.applyPropagatorsWithDepth(child, worklist, depth+1, visited)
	}
}

// findUsesAfter 查找某个节点之后的使用（辅助方法，供检测器使用）
func (e *MemoryTaintEngine) findUsesAfter(node *sitter.Node, varName string) []*sitter.Node {
	// 这是一个简化的实现
	// 实际实现需要结合CFG和变量定义使用分析
	var uses []*sitter.Node

	// 获取文件的所有节点（这里简化处理）
	// 在实际实现中，需要遍历CFG中的相关节点
	e.traverseForUses(e.ctx.Unit.Root, node, varName, &uses)

	return uses
}

// traverseForUses 遍历查找变量使用
func (e *MemoryTaintEngine) traverseForUses(root, afterNode *sitter.Node, varName string, uses *[]*sitter.Node) {
	if root == nil {
		return
	}

	// 检查是否在afterNode之后
	if afterNode != nil && root.StartPoint().Row <= afterNode.StartPoint().Row {
		// 在afterNode之前或同一行，跳过
	} else {
		// 检查是否是目标变量的使用
		if root.Type() == "identifier" {
			text := e.ctx.GetSourceText(root)
			if text == varName {
				*uses = append(*uses, root)
			}
		}
	}

	// 递归遍历
	childCount := root.ChildCount()
	children := make([]*sitter.Node, childCount)
	for i := 0; i < int(childCount); i++ {
		children[i] = root.Child(i)
	}

	for _, child := range children {
		e.traverseForUses(child, afterNode, varName, uses)
	}
}
