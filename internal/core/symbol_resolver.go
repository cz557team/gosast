package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
)

// SymbolResolver 符号解析器 - 实现两遍扫描法
type SymbolResolver struct {
	// 符号表
	symbolTable *SymbolTable
	// 文件缓存
	fileCache *FileCache
	// 上下文
	ctx context.Context
	// 并发控制
	workers int
	// 统计信息
	stats *SymbolResolverStats
}

// SymbolResolverStats 解析器统计信息
type SymbolResolverStats struct {
	FilesScanned     int           `json:"files_scanned"`
	SymbolsFound     int           `json:"symbols_found"`
	FunctionsFound   int           `json:"functions_found"`
	VariablesFound   int           `json:"variables_found"`
	MacrosFound      int           `json:"macros_found"`
	CallsResolved    int           `json:"calls_resolved"`
	IndexingTime     time.Duration `json:"indexing_time"`
	ResolutionTime   time.Duration `json:"resolution_time"`
	TotalTime        time.Duration `json:"total_time"`
	mutex            sync.Mutex
}

// NewSymbolResolver 创建新的符号解析器
func NewSymbolResolver(ctx context.Context, workers int) *SymbolResolver {
	return &SymbolResolver{
		symbolTable: NewSymbolTable(),
		fileCache:   NewFileCache(ctx),
		ctx:         ctx,
		workers:     workers,
		stats:       &SymbolResolverStats{},
	}
}

// IndexingPass 第一遍扫描：索引阶段
func (sr *SymbolResolver) IndexingPass(filePaths []string) error {
	startTime := time.Now()

	if isVerbose() {
	}

	// 创建工作池
	jobs := make(chan string, len(filePaths))
	errors := make(chan error, len(filePaths))
	var wg sync.WaitGroup

	// 启动工作协程
	for w := 0; w < sr.workers; w++ {
		wg.Add(1)
		go sr.indexingWorker(&wg, jobs, errors)
	}

	// 发送任务
	go func() {
		for _, filePath := range filePaths {
			select {
			case <-sr.ctx.Done():
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

	sr.stats.IndexingTime = time.Since(startTime)

	if len(errList) > 0 {
		return fmt.Errorf("索引阶段错误: %v", errList)
	}

	if isVerbose() {
	}

	return nil
}

// indexingWorker 索引工作协程
func (sr *SymbolResolver) indexingWorker(wg *sync.WaitGroup, jobs <-chan string, errors chan<- error) {
	defer wg.Done()

	for filePath := range jobs {
		select {
		case <-sr.ctx.Done():
			return
		default:
			if err := sr.indexFile(filePath); err != nil {
				errors <- fmt.Errorf("索引文件 %s 失败: %w", filePath, err)
			}
		}
	}
}

// indexFile 索引单个文件
func (sr *SymbolResolver) indexFile(filePath string) error {
	// 获取解析单元
	unit, err := sr.fileCache.Get(filePath)
	if err != nil {
		return err
	}

	sr.stats.FilesScanned++

	// 提取符号信息
	functions, variables, macros := sr.extractSymbolsFromUnit(unit)

	// 添加到符号表
	for _, fn := range functions {
		sr.symbolTable.AddSymbol(&Symbol{
			Name:       fn.Name,
			Type:       SymbolFunction,
			FilePath:   filePath,
			Line:       fn.StartLine,
			Column:     0,
			Signature:  fn.Signature,
			IsExported: sr.isFunctionExported(fn),
			ASTNode:    fn.ASTNode,
		})
		sr.stats.FunctionsFound++
		sr.stats.SymbolsFound++
	}

	for _, v := range variables {
		if v.IsGlobal {
			sr.symbolTable.AddSymbol(&Symbol{
				Name:       v.Name,
				Type:       SymbolVariable,
				FilePath:   filePath,
				Line:       v.StartLine,
				Column:     0,
				Signature:  v.Type,
				IsExported: true, // 全局变量默认为导出
				ASTNode:    v.ASTNode,
			})
			sr.stats.VariablesFound++
			sr.stats.SymbolsFound++
		}
	}

	for _, m := range macros {
		sr.symbolTable.AddSymbol(&Symbol{
			Name:       m.Name,
			Type:       SymbolMacro,
			FilePath:   filePath,
			Line:       m.StartLine,
			Column:     0,
			Signature:  m.Expansion,
			IsExported: true, // 宏默认为导出
			ASTNode:    m.ASTNode,
		})
		sr.stats.MacrosFound++
		sr.stats.SymbolsFound++
	}

	return nil
}

// extractSymbolsFromUnit 从解析单元提取符号
func (sr *SymbolResolver) extractSymbolsFromUnit(unit *ParseUnit) ([]*Function, []*Variable, []*Macro) {
	// 这里应该实现从AST中提取符号的逻辑
	// 目前返回缓存中的符号
	return unit.Functions, unit.Variables, unit.Macros
}

// isFunctionExported 检查函数是否导出
func (sr *SymbolResolver) isFunctionExported(fn *Function) bool {
	// C语言中，导出函数通常是首字母大写或没有static修饰符
	// 这里简化实现，假设所有非static函数都导出
	return true
}

// ResolutionPass 第二遍扫描：解析阶段（Phase 5 优化：并行化）
func (sr *SymbolResolver) ResolutionPass(filePaths []string) error {
	startTime := time.Now()

	if isVerbose() {
	}

	// 【Phase 5 优化】使用 worker pool 并行处理（类似 IndexingPass）
	// 创建工作池
	jobs := make(chan string, len(filePaths))
	errors := make(chan error, len(filePaths))
	var wg sync.WaitGroup

	// 启动工作协程
	for w := 0; w < sr.workers; w++ {
		wg.Add(1)
		go sr.resolutionWorker(&wg, jobs, errors)
	}

	// 发送任务
	go func() {
		for _, filePath := range filePaths {
			select {
			case <-sr.ctx.Done():
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

	sr.stats.ResolutionTime = time.Since(startTime)

	if len(errList) > 0 {
		return fmt.Errorf("解析阶段错误: %v", errList)
	}

	if isVerbose() {
	}

	return nil
}

// resolutionWorker 解析工作协程（Phase 5 优化）
func (sr *SymbolResolver) resolutionWorker(wg *sync.WaitGroup, jobs <-chan string, errors chan<- error) {
	defer wg.Done()

	for filePath := range jobs {
		select {
		case <-sr.ctx.Done():
			return
		default:
			if err := sr.resolveFileCalls(filePath); err != nil {
				errors <- fmt.Errorf("解析文件 %s 失败: %w", filePath, err)
			}
		}
	}
}

// resolveFileCalls 解析文件中的函数调用
func (sr *SymbolResolver) resolveFileCalls(filePath string) error {
	// 获取解析单元
	unit, err := sr.fileCache.Get(filePath)
	if err != nil {
		return err
	}

	// 查找函数调用
	callSites := sr.findCallSites(unit)

	for _, callSite := range callSites {
		// 解析调用
		symbol := sr.symbolTable.ResolveCall(callSite)
		if symbol != nil {
			sr.stats.CallsResolved++
			if isVerbose() {
			}
		}
	}

	return nil
}

// findCallSites 查找函数调用点
func (sr *SymbolResolver) findCallSites(unit *ParseUnit) []*CallSite {
	if unit == nil || unit.Tree == nil || unit.Tree.RootNode() == nil {
		return nil
	}

	callSites := make([]*CallSite, 0)
	root := unit.Tree.RootNode()

	// 递归查找所有调用表达式
	var findCalls func(*sitter.Node)
	findCalls = func(node *sitter.Node) {
		if node == nil {
			return
		}

		if node.Type() == "call_expression" {
			// 提取调用信息
			calleeName := sr.extractCalleeName(node, unit.Source)
			if calleeName != "" {
				callSite := &CallSite{
					CalleeName: calleeName,
					CallerFile: unit.FilePath,
					CallerLine: int(node.StartPoint().Row) + 1,
					CallerNode: node,
					Arguments:  sr.extractCallArguments(node),
				}
				callSites = append(callSites, callSite)
			}
		}

		// 递归遍历子节点
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil {
				findCalls(child)
			}
		}
	}

	findCalls(root)
	return callSites
}

// extractCalleeName 从调用表达式中提取被调用函数名
func (sr *SymbolResolver) extractCalleeName(callNode *sitter.Node, source []byte) string {
	if callNode.Type() != "call_expression" {
		return ""
	}

	funcNode := callNode.ChildByFieldName("function")
	if funcNode == nil {
		return ""
	}

	// 递归查找标识符
	return sr.findIdentifierInNode(funcNode, source)
}

// findIdentifierInNode 在节点中查找标识符
func (sr *SymbolResolver) findIdentifierInNode(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}

	if node.Type() == "identifier" {
		startByte := int(node.StartByte())
		endByte := int(node.EndByte())

		if startByte >= 0 && endByte >= startByte && endByte <= len(source) {
			return string(source[startByte:endByte])
		}
	}

	// 递归查找
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			if ident := sr.findIdentifierInNode(child, source); ident != "" {
				return ident
			}
		}
	}

	return ""
}

// extractCallArguments 提取调用参数
func (sr *SymbolResolver) extractCallArguments(callNode *sitter.Node) []interface{} {
	if callNode.Type() != "call_expression" {
		return nil
	}

	argumentsNode := callNode.ChildByFieldName("arguments")
	if argumentsNode == nil {
		return nil
	}

	arguments := make([]interface{}, 0)
	for i := 0; i < int(argumentsNode.ChildCount()); i++ {
		child := argumentsNode.Child(i)
		if child != nil && child.Type() != "(" && child.Type() != ")" {
			arguments = append(arguments, child)
		}
	}

	return arguments
}

// GetSymbolTable 获取符号表
func (sr *SymbolResolver) GetSymbolTable() *SymbolTable {
	return sr.symbolTable
}

// GetFileCache 获取文件缓存
func (sr *SymbolResolver) GetFileCache() *FileCache {
	return sr.fileCache
}

// GetStats 获取统计信息
func (sr *SymbolResolver) GetStats() *SymbolResolverStats {
	sr.stats.TotalTime = sr.stats.IndexingTime + sr.stats.ResolutionTime
	return sr.stats
}

// Process 执行完整的两遍扫描
func (sr *SymbolResolver) Process(filePaths []string) error {
	// 第一遍：索引阶段
	if err := sr.IndexingPass(filePaths); err != nil {
		return err
	}

	// 第二遍：解析阶段
	if err := sr.ResolutionPass(filePaths); err != nil {
		return err
	}

	return nil
}

// ResolveFunctionCall 解析单个函数调用
func (sr *SymbolResolver) ResolveFunctionCall(calleeName, callerFile string) *Symbol {
	return sr.symbolTable.GetSymbol(calleeName, callerFile)
}

// FindCallees 查找被调用的函数
func (sr *SymbolResolver) FindCallees(filePath string) []string {
	unit, err := sr.fileCache.Get(filePath)
	if err != nil {
		return nil
	}

	// 从函数列表中提取被调用函数
	callees := make([]string, 0)
	for _, fn := range unit.Functions {
		callees = append(callees, fn.Callees...)
	}

	return callees
}

// GetCrossFileDependencies 获取跨文件依赖关系
func (sr *SymbolResolver) GetCrossFileDependencies(filePath string) map[string][]string {
	dependencies := make(map[string][]string)

	unit, err := sr.fileCache.Get(filePath)
	if err != nil {
		return dependencies
	}

	for _, fn := range unit.Functions {
		for _, calleeName := range fn.Callees {
			symbol := sr.symbolTable.GetSymbol(calleeName, filePath)
			if symbol != nil && symbol.FilePath != filePath {
				dependencies[calleeName] = append(dependencies[calleeName], symbol.FilePath)
			}
		}
	}

	return dependencies
}
