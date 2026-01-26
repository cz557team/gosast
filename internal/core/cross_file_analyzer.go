package core

import (
	"context"
	"fmt"
	"sync"
)

// CrossFileAnalyzer 跨文件分析器
type CrossFileAnalyzer struct {
	// 符号解析器
	resolver *SymbolResolver
	// 并发控制
	workers int
	// 上下文
	ctx context.Context
	// 分析结果
	analysisResults []*CrossFileVulnerability
	// 互斥锁
	mutex sync.Mutex
}

// CrossFileVulnerability 跨文件漏洞
type CrossFileVulnerability struct {
	Type           string            `json:"type"`             // 漏洞类型
	Message        string            `json:"message"`          // 漏洞描述
	SourceFile     string            `json:"source_file"`      // 源文件
	SourceLine     int               `json:"source_line"`      // 源行
	TargetFile     string            `json:"target_file"`      // 目标文件
	TargetLine     int               `json:"target_line"`      // 目标行
	Severity       string            `json:"severity"`         // 严重性
	Confidence     string            `json:"confidence"`       // 置信度
	CallChain      []CallChainNode   `json:"call_chain"`       // 调用链
	Metadata       map[string]interface{} `json:"metadata"`   // 元数据
}

// CallChainNode 调用链节点
type CallChainNode struct {
	Function   string `json:"function"`   // 函数名
	FilePath   string `json:"file_path"`  // 文件路径
	Line       int    `json:"line"`       // 行号
	IsSource   bool   `json:"is_source"`  // 是否为源头
	IsSink     bool   `json:"is_sink"`    // 是否为终点
}

// NewCrossFileAnalyzer 创建新的跨文件分析器
func NewCrossFileAnalyzer(ctx context.Context, workers int) *CrossFileAnalyzer {
	return &CrossFileAnalyzer{
		resolver:        NewSymbolResolver(ctx, workers),
		workers:         workers,
		ctx:             ctx,
		analysisResults: make([]*CrossFileVulnerability, 0),
	}
}

// AnalyzeProject 分析整个项目
func (cfa *CrossFileAnalyzer) AnalyzeProject(filePaths []string) error {
	// 第一步：构建符号表
	if err := cfa.resolver.Process(filePaths); err != nil {
		return fmt.Errorf("符号解析失败: %w", err)
	}

	// 第二步：执行跨文件分析
	if err := cfa.performCrossFileAnalysis(filePaths); err != nil {
		return fmt.Errorf("跨文件分析失败: %w", err)
	}

	return nil
}

// performCrossFileAnalysis 执行跨文件分析
func (cfa *CrossFileAnalyzer) performCrossFileAnalysis(filePaths []string) error {
	// 创建工作池
	jobs := make(chan string, len(filePaths))
	errors := make(chan error, len(filePaths))
	var wg sync.WaitGroup

	// 启动工作协程
	for w := 0; w < cfa.workers; w++ {
		wg.Add(1)
		go cfa.analysisWorker(&wg, jobs, errors)
	}

	// 发送任务
	go func() {
		for _, filePath := range filePaths {
			select {
			case <-cfa.ctx.Done():
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
		return fmt.Errorf("跨文件分析错误: %v", errList)
	}

	return nil
}

// analysisWorker 分析工作协程
func (cfa *CrossFileAnalyzer) analysisWorker(wg *sync.WaitGroup, jobs <-chan string, errors chan<- error) {
	defer wg.Done()

	for filePath := range jobs {
		select {
		case <-cfa.ctx.Done():
			return
		default:
			if err := cfa.analyzeFile(filePath); err != nil {
				errors <- fmt.Errorf("分析文件 %s 失败: %w", filePath, err)
			}
		}
	}
}

// analyzeFile 分析单个文件
func (cfa *CrossFileAnalyzer) analyzeFile(filePath string) error {
	// 获取依赖关系
	dependencies := cfa.resolver.GetCrossFileDependencies(filePath)

	// 分析跨文件调用
	for callee, targets := range dependencies {
		for _, targetFile := range targets {
			vuln := cfa.analyzeCrossFileCall(filePath, callee, targetFile)
			if vuln != nil {
				cfa.addVulnerability(vuln)
			}
		}
	}

	return nil
}

// analyzeCrossFileCall 分析跨文件调用
func (cfa *CrossFileAnalyzer) analyzeCrossFileCall(sourceFile, calleeName, targetFile string) *CrossFileVulnerability {
	// 获取符号信息
	symbol := cfa.resolver.ResolveFunctionCall(calleeName, sourceFile)
	if symbol == nil {
		return nil
	}

	// 构建调用链
	callChain := cfa.buildCallChain(sourceFile, calleeName, targetFile)

	// 检测潜在漏洞
	if cfa.isPotentialVulnerability(calleeName, targetFile) {
		return &CrossFileVulnerability{
			Type:           "Cross-File Vulnerability",
			Message:        fmt.Sprintf("跨文件调用 %s 存在潜在安全风险", calleeName),
			SourceFile:     sourceFile,
			SourceLine:     0,
			TargetFile:     targetFile,
			TargetLine:     symbol.Line,
			Severity:       "medium",
			Confidence:     "low",
			CallChain:      callChain,
			Metadata:       map[string]interface{}{"callee": calleeName},
		}
	}

	return nil
}

// buildCallChain 构建调用链
func (cfa *CrossFileAnalyzer) buildCallChain(sourceFile, calleeName, targetFile string) []CallChainNode {
	chain := make([]CallChainNode, 0)

	// 添加源节点
	chain = append(chain, CallChainNode{
		Function: calleeName,
		FilePath: sourceFile,
		Line:     0,
		IsSource: true,
		IsSink:   false,
	})

	// 添加目标节点
	symbol := cfa.resolver.ResolveFunctionCall(calleeName, sourceFile)
	if symbol != nil {
		chain = append(chain, CallChainNode{
			Function: calleeName,
			FilePath: targetFile,
			Line:     symbol.Line,
			IsSource: false,
			IsSink:   cfa.isSinkFunction(calleeName),
		})
	}

	return chain
}

// isPotentialVulnerability 检查是否为潜在漏洞
func (cfa *CrossFileAnalyzer) isPotentialVulnerability(calleeName, targetFile string) bool {
	// 简单的启发式规则：
	// 1. 如果调用的是系统函数（如exec, system等）
	// 2. 如果函数名包含敏感关键词（如copy, free, malloc等）
	sensitiveFuncs := []string{"exec", "system", "popen", "strcpy", "strcat", "malloc", "free"}

	for _, sensitive := range sensitiveFuncs {
		if calleeName == sensitive {
			return true
		}
	}

	return false
}

// isSinkFunction 检查是否为Sink函数
func (cfa *CrossFileAnalyzer) isSinkFunction(funcName string) bool {
	sinkFuncs := []string{"exec", "system", "popen", "eval"}
	for _, sink := range sinkFuncs {
		if funcName == sink {
			return true
		}
	}
	return false
}

// addVulnerability 添加漏洞
func (cfa *CrossFileAnalyzer) addVulnerability(vuln *CrossFileVulnerability) {
	cfa.mutex.Lock()
	defer cfa.mutex.Unlock()

	cfa.analysisResults = append(cfa.analysisResults, vuln)
}

// GetResults 获取分析结果
func (cfa *CrossFileAnalyzer) GetResults() []*CrossFileVulnerability {
	cfa.mutex.Lock()
	defer cfa.mutex.Unlock()

	// 返回副本，避免外部修改
	results := make([]*CrossFileVulnerability, len(cfa.analysisResults))
	copy(results, cfa.analysisResults)
	return results
}

// GetResultsByType 按类型获取结果
func (cfa *CrossFileAnalyzer) GetResultsByType(vulnType string) []*CrossFileVulnerability {
	cfa.mutex.Lock()
	defer cfa.mutex.Unlock()

	var filtered []*CrossFileVulnerability
	for _, vuln := range cfa.analysisResults {
		if vuln.Type == vulnType {
			filtered = append(filtered, vuln)
		}
	}
	return filtered
}

// GetStats 获取分析统计
func (cfa *CrossFileAnalyzer) GetStats() map[string]interface{} {
	cfa.mutex.Lock()
	defer cfa.mutex.Unlock()

	stats := map[string]interface{}{
		"total_vulnerabilities": len(cfa.analysisResults),
		"by_severity":           make(map[string]int),
		"by_source_file":        make(map[string]int),
		"by_target_file":        make(map[string]int),
	}

	for _, vuln := range cfa.analysisResults {
		stats["by_severity"].(map[string]int)[vuln.Severity]++
		stats["by_source_file"].(map[string]int)[vuln.SourceFile]++
		stats["by_target_file"].(map[string]int)[vuln.TargetFile]++
	}

	return stats
}

// Clear 清空结果
func (cfa *CrossFileAnalyzer) Clear() {
	cfa.mutex.Lock()
	defer cfa.mutex.Unlock()

	cfa.analysisResults = make([]*CrossFileVulnerability, 0)
}

// GetSymbolResolver 获取符号解析器
func (cfa *CrossFileAnalyzer) GetSymbolResolver() *SymbolResolver {
	return cfa.resolver
}

// AnalyzeTaintFlow 分析污点跨文件传播
func (cfa *CrossFileAnalyzer) AnalyzeTaintFlow(sourceFunc, sinkFunc string) []*CrossFileVulnerability {
	// 这里实现污点传播分析
	// 目前简化实现，返回空列表
	return []*CrossFileVulnerability{}
}
