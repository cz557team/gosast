package core

import (
	"context"
	"fmt"
	"sync"
)

// CrossFileTaintAnalyzer 跨文件污点分析器
type CrossFileTaintAnalyzer struct {
	// 符号解析器
	resolver *SymbolResolver
	// 污点引擎映射 (每个文件一个)
	taintEngines map[string]*MemoryTaintEngine
	// 跨文件污点传播规则
	crossFileRules []CrossFileTaintRule
	// 上下文
	ctx context.Context
	// 并发控制
	mutex sync.RWMutex
	// 分析结果
	results []*CrossFileTaintResult
	// 【Phase 5 优化】CFG 缓存（从外部传入）
	cfgCache    map[string]*CFG
	cfgCacheMu  *sync.RWMutex
	// 【Phase 5 优化】worker 数量
	workers int
}

// CrossFileTaintRule 跨文件污点传播规则
type CrossFileTaintRule struct {
	SourceFunc string   `json:"source_func"` // 源函数名
	SinkFunc   string   `json:"sink_func"`   // 目标函数名
	ArgMap     []int    `json:"arg_map"`     // 参数映射 (源参数索引 -> 目标参数索引)
	Sanitizers []string `json:"sanitizers"`  // 净化函数列表
}

// CrossFileTaintResult 跨文件污点分析结果
type CrossFileTaintResult struct {
	SourceFile     string            `json:"source_file"`
	SourceLine     int               `json:"source_line"`
	TargetFile     string            `json:"target_file"`
	TargetLine     int               `json:"target_line"`
	TaintPath      []TaintPathNode   `json:"taint_path"`
	Vulnerability  string            `json:"vulnerability"`
	Severity       string            `json:"severity"`
	Confidence     string            `json:"confidence"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// TaintPathNode 污点路径节点
type TaintPathNode struct {
	FilePath   string `json:"file_path"`
	Function   string `json:"function"`
	Line       int    `json:"line"`
	NodeType   string `json:"node_type"`
	IsSource   bool   `json:"is_source"`
	IsSink     bool   `json:"is_sink"`
	ArgIndex   int    `json:"arg_index,omitempty"` // 参数索引（如果是函数调用）
}

// NewCrossFileTaintAnalyzer 创建新的跨文件污点分析器
func NewCrossFileTaintAnalyzer(ctx context.Context, resolver *SymbolResolver) *CrossFileTaintAnalyzer {
	analyzer := &CrossFileTaintAnalyzer{
		resolver:      resolver,
		taintEngines:  make(map[string]*MemoryTaintEngine),
		crossFileRules: make([]CrossFileTaintRule, 0),
		ctx:           ctx,
		results:       make([]*CrossFileTaintResult, 0),
		cfgCache:      nil,       // 默认无缓存
		cfgCacheMu:    nil,
		workers:       4,         // 默认 4 个 worker
	}

	// 注册默认的跨文件污点规则
	analyzer.registerDefaultRules()

	return analyzer
}

// SetCFGCache 设置 CFG 缓存和 worker 数量（Phase 5 优化）
func (cfta *CrossFileTaintAnalyzer) SetCFGCache(cache map[string]*CFG, mu *sync.RWMutex) {
	cfta.cfgCache = cache
	cfta.cfgCacheMu = mu
}

// SetWorkers 设置 worker 数量（Phase 5 优化）
func (cfta *CrossFileTaintAnalyzer) SetWorkers(workers int) {
	cfta.workers = workers
}

// registerDefaultRules 注册默认的跨文件污点传播规则
func (cfta *CrossFileTaintAnalyzer) registerDefaultRules() {
	// 规则1: 从外部输入到危险函数
	cfta.crossFileRules = append(cfta.crossFileRules, CrossFileTaintRule{
		SourceFunc: "scanf",
		SinkFunc:   "strcpy",
		ArgMap:     []int{1, 0}, // scanf的第二个参数 -> strcpy的目标
		Sanitizers: []string{"sanitize", "validate"},
	})

	// 规则2: 从网络输入到命令执行
	cfta.crossFileRules = append(cfta.crossFileRules, CrossFileTaintRule{
		SourceFunc: "recv",
		SinkFunc:   "system",
		ArgMap:     []int{2, 0}, // recv的缓冲区 -> system的命令
		Sanitizers: []string{"escape_shell_cmd"},
	})

	// 规则3: 文件读取到缓冲区操作
	cfta.crossFileRules = append(cfta.crossFileRules, CrossFileTaintRule{
		SourceFunc: "fread",
		SinkFunc:   "printf",
		ArgMap:     []int{0, 0}, // fread的缓冲区 -> printf的格式串
		Sanitizers: []string{"filter_format"},
	})
}

// AddTaintEngine 为文件添加污点引擎
func (cfta *CrossFileTaintAnalyzer) AddTaintEngine(filePath string, engine *MemoryTaintEngine) {
	cfta.mutex.Lock()
	defer cfta.mutex.Unlock()

	cfta.taintEngines[filePath] = engine
}

// AnalyzeProject 分析整个项目的跨文件污点传播
func (cfta *CrossFileTaintAnalyzer) AnalyzeProject(filePaths []string) error {
	if isVerbose() {
	}

	// 第一步：为每个文件创建污点引擎（如果不存在）
	cfta.initializeTaintEngines(filePaths)

	// 第二步：执行单文件污点分析
	if err := cfta.performPerFileTaintAnalysis(filePaths); err != nil {
		return fmt.Errorf("单文件污点分析失败: %w", err)
	}

	// 第三步：执行跨文件污点传播分析
	if err := cfta.performCrossFileTaintPropagation(filePaths); err != nil {
		return fmt.Errorf("跨文件污点传播分析失败: %w", err)
	}

	if isVerbose() {
	}

	return nil
}

// initializeTaintEngines 初始化污点引擎
func (cfta *CrossFileTaintAnalyzer) initializeTaintEngines(filePaths []string) {
	for _, filePath := range filePaths {
		if _, exists := cfta.taintEngines[filePath]; !exists {
			// 创建分析上下文
			unit, err := cfta.resolver.GetFileCache().Get(filePath)
			if err != nil {
				continue
			}

			// 将 ParseUnit 转换为 ParsedUnit
			parsedUnit := &ParsedUnit{
				FilePath: unit.FilePath,
				Root:     unit.Tree.RootNode(),
				Source:   unit.Source,
				Tree:     unit.Tree,
				Language: "c", // 默认语言
			}

			ctx := NewAnalysisContext(parsedUnit)
			ctx.SymbolResolver = cfta.resolver

			// 创建污点引擎
			engine := NewMemoryTaintEngine(ctx)
			cfta.AddTaintEngine(filePath, engine)
		}
	}
}

// performPerFileTaintAnalysis 执行单文件污点分析（Phase 5 优化：并行化）
func (cfta *CrossFileTaintAnalyzer) performPerFileTaintAnalysis(filePaths []string) error {
	// 【Phase 5 优化】使用 worker pool 并行处理
	jobs := make(chan string, len(filePaths))
	errors := make(chan error, len(filePaths))
	var wg sync.WaitGroup

	// 启动工作协程
	for w := 0; w < cfta.workers; w++ {
		wg.Add(1)
		go cfta.taintAnalysisWorker(&wg, jobs, errors)
	}

	// 发送任务
	go func() {
		for _, filePath := range filePaths {
			select {
			case <-cfta.ctx.Done():
				return
			case jobs <- filePath:
			}
		}
		close(jobs)
	}()

	// 等待完成
	go func() {
		wg.Wait()
		close(errors)
	}()

	// 收集错误
	var errList []error
	for err := range errors {
		errList = append(errList, err)
	}

	if len(errList) > 0 {
		return fmt.Errorf("污点分析阶段错误: %v", errList)
	}

	return nil
}

// taintAnalysisWorker 污点分析工作协程（Phase 5 优化）
func (cfta *CrossFileTaintAnalyzer) taintAnalysisWorker(wg *sync.WaitGroup, jobs <-chan string, errors chan<- error) {
	defer wg.Done()

	for filePath := range jobs {
		select {
		case <-cfta.ctx.Done():
			return
		default:
			engine := cfta.taintEngines[filePath]
			if engine == nil {
				continue
			}

			// 获取文件解析单元
			unit, err := cfta.resolver.GetFileCache().Get(filePath)
			if err != nil {
				errors <- fmt.Errorf("获取文件缓存失败 %s: %w", filePath, err)
				continue
			}

			// 将 ParseUnit 转换为 ParsedUnit
			parsedUnit := &ParsedUnit{
				FilePath: unit.FilePath,
				Root:     unit.Tree.RootNode(),
				Source:   unit.Source,
				Tree:     unit.Tree,
				Language: "c", // 默认语言
			}

			// 【Phase 5 优化】优先使用缓存的 CFG
			var cfg *CFG
			if cfta.cfgCache != nil && cfta.cfgCacheMu != nil {
				cfta.cfgCacheMu.RLock()
				if cachedCFG, exists := cfta.cfgCache[filePath]; exists {
					cfg = cachedCFG
				}
				cfta.cfgCacheMu.RUnlock()
			}

			// 如果缓存中没有，则构建新的 CFG
			if cfg == nil {
				cfg, err = BuildCFG(parsedUnit)
				if err != nil {
					if isVerbose() {
					}
					continue
				}
			}

			if cfg != nil {
				if err := engine.Propagate(cfg); err != nil {
					if isVerbose() {
					}
					errors <- fmt.Errorf("污点传播失败 %s: %w", filePath, err)
				}
			}
		}
	}
}

// performCrossFileTaintPropagation 执行跨文件污点传播分析
func (cfta *CrossFileTaintAnalyzer) performCrossFileTaintPropagation(filePaths []string) error {
	for _, filePath := range filePaths {
		// 获取跨文件依赖
		dependencies := cfta.resolver.GetCrossFileDependencies(filePath)

		for callee, targetFiles := range dependencies {
			for _, targetFile := range targetFiles {
				// 分析跨文件调用
				if err := cfta.analyzeCrossFileCall(filePath, callee, targetFile); err != nil {
					if isVerbose() {
					}
				}
			}
		}
	}

	return nil
}

// analyzeCrossFileCall 分析跨文件调用
func (cfta *CrossFileTaintAnalyzer) analyzeCrossFileCall(sourceFile, calleeName, targetFile string) error {
	sourceEngine := cfta.taintEngines[sourceFile]
	targetEngine := cfta.taintEngines[targetFile]

	if sourceEngine == nil || targetEngine == nil {
		return nil
	}

	// 获取调用点信息
	callSites := cfta.findCallSitesInFile(sourceFile, calleeName)
	if len(callSites) == 0 {
		return nil
	}

	// 获取目标函数信息
	targetSymbol := cfta.resolver.ResolveFunctionCall(calleeName, sourceFile)
	if targetSymbol == nil {
		return nil
	}

	// 应用跨文件污点规则
	for _, rule := range cfta.crossFileRules {
		if rule.SourceFunc == calleeName || rule.SinkFunc == calleeName {
			// 检查是否匹配污点规则
			if result := cfta.checkTaintRule(sourceFile, targetFile, callSites, rule, targetSymbol); result != nil {
				cfta.addResult(result)
			}
		}
	}

	return nil
}

// findCallSitesInFile 在文件中查找特定函数的调用点
func (cfta *CrossFileTaintAnalyzer) findCallSitesInFile(filePath, calleeName string) []*CallSite {
	unit, err := cfta.resolver.GetFileCache().Get(filePath)
	if err != nil {
		return nil
	}

	callSites := cfta.resolver.findCallSites(unit)
	filtered := make([]*CallSite, 0)

	for _, callSite := range callSites {
		if callSite.CalleeName == calleeName {
			filtered = append(filtered, callSite)
		}
	}

	return filtered
}

// checkTaintRule 检查污点规则
func (cfta *CrossFileTaintAnalyzer) checkTaintRule(sourceFile, targetFile string, callSites []*CallSite, rule CrossFileTaintRule, targetSymbol *Symbol) *CrossFileTaintResult {
	// 简化实现：检查是否有匹配的调用模式
	if len(callSites) > 0 {
		// 构建污点路径
		taintPath := cfta.buildTaintPath(sourceFile, targetFile, callSites[0], targetSymbol)

		return &CrossFileTaintResult{
			SourceFile:    sourceFile,
			SourceLine:    callSites[0].CallerLine,
			TargetFile:    targetFile,
			TargetLine:    targetSymbol.Line,
			TaintPath:     taintPath,
			Vulnerability: fmt.Sprintf("Potential taint flow: %s -> %s", rule.SourceFunc, rule.SinkFunc),
			Severity:      "medium",
			Confidence:    "low",
			Metadata: map[string]interface{}{
				"source_func": rule.SourceFunc,
				"sink_func":   rule.SinkFunc,
				"rule_match":  true,
			},
		}
	}

	return nil
}

// buildTaintPath 构建污点路径
func (cfta *CrossFileTaintAnalyzer) buildTaintPath(sourceFile, targetFile string, callSite *CallSite, targetSymbol *Symbol) []TaintPathNode {
	path := make([]TaintPathNode, 0)

	// 添加源节点
	path = append(path, TaintPathNode{
		FilePath: sourceFile,
		Function: callSite.CalleeName,
		Line:     callSite.CallerLine,
		NodeType: "call_expression",
		IsSource: true,
	})

	// 添加目标节点
	path = append(path, TaintPathNode{
		FilePath: targetFile,
		Function: targetSymbol.Name,
		Line:     targetSymbol.Line,
		NodeType: "function_definition",
		IsSink:   true,
	})

	return path
}

// addResult 添加分析结果
func (cfta *CrossFileTaintAnalyzer) addResult(result *CrossFileTaintResult) {
	cfta.mutex.Lock()
	defer cfta.mutex.Unlock()

	cfta.results = append(cfta.results, result)
}

// GetResults 获取分析结果
func (cfta *CrossFileTaintAnalyzer) GetResults() []*CrossFileTaintResult {
	cfta.mutex.RLock()
	defer cfta.mutex.RUnlock()

	// 返回副本
	results := make([]*CrossFileTaintResult, len(cfta.results))
	copy(results, cfta.results)
	return results
}

// GetStats 获取统计信息
func (cfta *CrossFileTaintAnalyzer) GetStats() map[string]interface{} {
	cfta.mutex.RLock()
	defer cfta.mutex.RUnlock()

	return map[string]interface{}{
		"total_results":  len(cfta.results),
		"files_analyzed": len(cfta.taintEngines),
		"rules_registered": len(cfta.crossFileRules),
	}
}
