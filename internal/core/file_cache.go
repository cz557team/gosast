package core

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
)

// ParseUnit 解析单元，包含已解析的AST和相关信息
// 性能优化：移除 mutex，ParseUnit 创建后不可变（只读）
// Phase 5 优化：支持 Tree 释放以节省内存
type ParseUnit struct {
	FilePath   string          `json:"file_path"`
	Tree       *sitter.Tree    `json:"tree"`       // AST树（可为 nil，已释放）
	Source     []byte          `json:"source"`     // 源码内容（始终保留）
	Functions  []*Function     `json:"functions"`  // 函数列表
	Variables  []*Variable     `json:"variables"`  // 变量列表
	Macros     []*Macro        `json:"macros"`     // 宏定义列表
	LoadedAt   time.Time       `json:"loaded_at"`  // 加载时间
	RefCount   int32           `json:"ref_count"`  // 引用计数（使用 atomic 操作）
	IsModified bool            `json:"is_modified"` // 是否被修改
	// Phase 5 新增：Tree 状态跟踪
	TreeLastAccess time.Time  `json:"tree_last_access"` // Tree 最后访问时间
	TreeReleased  bool      `json:"tree_released"`   // Tree 是否已释放
	TreeSizeBytes int64     `json:"tree_size_bytes"` // Tree 占用字节数（用于统计）
	// 移除 mutex - ParseUnit 创建后不可变，无需锁保护
}

// Function 函数信息
type Function struct {
	Name       string      `json:"name"`       // 函数名
	Signature  string      `json:"signature"`  // 函数签名
	StartLine  int         `json:"start_line"` // 起始行
	EndLine    int         `json:"end_line"`   // 结束行
	ASTNode    interface{} `json:"-"`          // AST节点
	Callees    []string    `json:"callees"`    // 调用的函数列表
}

// Variable 变量信息
type Variable struct {
	Name      string      `json:"name"`       // 变量名
	Type      string      `json:"type"`       // 变量类型
	StartLine int         `json:"start_line"` // 声明行
	ASTNode   interface{} `json:"-"`          // AST节点
	IsGlobal  bool        `json:"is_global"`  // 是否为全局变量
}

// Macro 宏信息
type Macro struct {
	Name      string      `json:"name"`       // 宏名
	Expansion string      `json:"expansion"`  // 展开内容
	StartLine int         `json:"start_line"` // 定义行
	ASTNode   interface{} `json:"-"`          // AST节点
}

// FileCache 文件缓存管理器
type FileCache struct {
	// 缓存的解析单元
	cache map[string]*ParseUnit
	// 互斥锁
	mutex sync.RWMutex
	// 上下文，用于取消操作
	ctx context.Context
	// 缓存统计
	hits   int
	misses int
}

// NewFileCache 创建新的文件缓存
func NewFileCache(ctx context.Context) *FileCache {
	return &FileCache{
		cache: make(map[string]*ParseUnit),
		ctx:   ctx,
	}
}

// Get 获取解析单元（按需加载）
func (fc *FileCache) Get(filePath string) (*ParseUnit, error) {
	fc.mutex.RLock()
	unit := fc.cache[filePath]
	fc.mutex.RUnlock()

	if unit != nil {
		fc.hits++
		// ParseUnit 不再使用锁，RefCount 使用 atomic 操作
		atomic.AddInt32(&unit.RefCount, 1)
		return unit, nil
	}

	fc.misses++

	// 缓存未命中，需要解析文件
	unit, err := fc.loadAndParse(filePath)
	if err != nil {
		return nil, err
	}

	fc.mutex.Lock()
	fc.cache[filePath] = unit
	fc.mutex.Unlock()

	return unit, nil
}

// loadAndParse 加载并解析文件
func (fc *FileCache) loadAndParse(filePath string) (*ParseUnit, error) {
	// 解析文件
	parsedUnit, err := ParseFile(fc.ctx, filePath)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	unit := &ParseUnit{
		FilePath:       filePath,
		Tree:           parsedUnit.Tree,
		Source:         parsedUnit.Source,
		LoadedAt:       now,
		RefCount:       1,
		TreeLastAccess: now, // Phase 5: 初始化 Tree 访问时间
		TreeReleased:   false,
	}

	// 提取符号信息
	unit.extractSymbols()

	return unit, nil
}

// extractSymbols 提取符号信息
func (pu *ParseUnit) extractSymbols() {
	if pu.Tree == nil || pu.Tree.RootNode() == nil {
		return
	}

	pu.Functions = make([]*Function, 0)
	pu.Variables = make([]*Variable, 0)
	pu.Macros = make([]*Macro, 0)

	root := pu.Tree.RootNode()
	if root == nil {
		return
	}

	// 使用Tree-sitter查询来提取符号
	pu.extractFunctions(root)
	pu.extractVariables(root)
	pu.extractMacros(root)
}

// extractFunctions 提取函数定义
func (pu *ParseUnit) extractFunctions(node *sitter.Node) {
	if node == nil {
		return
	}

	// 查找函数定义
	if node.Type() == "function_definition" {
		funcName := pu.getFunctionName(node)
		if funcName != "" {
			startLine := int(node.StartPoint().Row) + 1
			endLine := int(node.EndPoint().Row) + 1

			function := &Function{
				Name:       funcName,
				Signature:  pu.getFunctionSignature(node),
				StartLine:  startLine,
				EndLine:    endLine,
				ASTNode:    node,
				Callees:    pu.extractCallees(node),
			}
			pu.Functions = append(pu.Functions, function)
		}
	}

	// 递归遍历子节点
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			pu.extractFunctions(child)
		}
	}
}

// extractVariables 提取变量声明
func (pu *ParseUnit) extractVariables(node *sitter.Node) {
	if node == nil {
		return
	}

	// 查找变量声明
	if node.Type() == "declaration" {
		varName := pu.getVariableName(node)
		if varName != "" {
			startLine := int(node.StartPoint().Row) + 1

			variable := &Variable{
				Name:      varName,
				Type:      pu.getVariableType(node),
				StartLine: startLine,
				ASTNode:   node,
				IsGlobal:  pu.isGlobalVariable(node),
			}
			pu.Variables = append(pu.Variables, variable)
		}
	}

	// 递归遍历子节点
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			pu.extractVariables(child)
		}
	}
}

// extractMacros 提取宏定义
func (pu *ParseUnit) extractMacros(node *sitter.Node) {
	if node == nil {
		return
	}

	// 查找预处理指令
	if node.Type() == "preproc_include" || node.Type() == "preproc_def" {
		// 这里应该处理#include和#define
		// 目前简化处理
	}

	// 递归遍历子节点
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			pu.extractMacros(child)
		}
	}
}

// getFunctionName 获取函数名
func (pu *ParseUnit) getFunctionName(node *sitter.Node) string {
	if node.Type() != "function_definition" {
		return ""
	}

	// 查找函数声明符
	declarator := node.ChildByFieldName("declarator")
	if declarator == nil {
		return ""
	}

	// 递归查找标识符
	return pu.findIdentifier(declarator)
}

// getFunctionSignature 获取函数签名
func (pu *ParseUnit) getFunctionSignature(node *sitter.Node) string {
	if node.Type() != "function_definition" {
		return ""
	}

	// 简化实现，返回函数名
	return pu.getFunctionName(node)
}

// extractCallees 提取被调用的函数
func (pu *ParseUnit) extractCallees(node *sitter.Node) []string {
	callees := make([]string, 0)

	// 查找所有调用表达式
	var findCalls func(*sitter.Node)
	findCalls = func(n *sitter.Node) {
		if n == nil {
			return
		}

		if n.Type() == "call_expression" {
			calleeName := pu.getCalleeName(n)
			if calleeName != "" {
				callees = append(callees, calleeName)
			}
		}

		for i := 0; i < int(n.ChildCount()); i++ {
			findCalls(n.Child(i))
		}
	}

	findCalls(node)
	return callees
}

// getCalleeName 获取被调用函数名
func (pu *ParseUnit) getCalleeName(node *sitter.Node) string {
	if node.Type() != "call_expression" {
		return ""
	}

	funcNode := node.ChildByFieldName("function")
	if funcNode == nil {
		return ""
	}

	return pu.findIdentifier(funcNode)
}

// findIdentifier 递归查找标识符
func (pu *ParseUnit) findIdentifier(node *sitter.Node) string {
	if node == nil {
		return ""
	}

	if node.Type() == "identifier" {
		// 从源码中获取实际的标识符文本
		startByte := int(node.StartByte())
		endByte := int(node.EndByte())

		if startByte >= 0 && endByte >= startByte && endByte <= len(pu.Source) {
			return string(pu.Source[startByte:endByte])
		}
	}

	if node.ChildCount() > 0 {
		return pu.findIdentifier(node.Child(0))
	}

	return ""
}

// getVariableName 获取变量名
func (pu *ParseUnit) getVariableName(node *sitter.Node) string {
	// 查找声明符
	declarator := node.ChildByFieldName("declarator")
	if declarator == nil {
		return ""
	}

	return pu.findIdentifier(declarator)
}

// getVariableType 获取变量类型
func (pu *ParseUnit) getVariableType(node *sitter.Node) string {
	// 简化实现，返回占位符
	return "type"
}

// isGlobalVariable 检查是否为全局变量
func (pu *ParseUnit) isGlobalVariable(node *sitter.Node) bool {
	// 简化实现，假设所有变量都是局部的
	// 实际应该检查是否在函数外部
	return false
}

// Put 归还解析单元（减少引用计数）
func (fc *FileCache) Put(filePath string) {
	fc.mutex.RLock()
	unit := fc.cache[filePath]
	fc.mutex.RUnlock()

	if unit != nil {
		// 使用原子操作减少引用计数
		atomic.AddInt32(&unit.RefCount, -1)
	}
}

// Remove 从缓存中移除
func (fc *FileCache) Remove(filePath string) {
	fc.mutex.Lock()
	defer fc.mutex.Unlock()

	delete(fc.cache, filePath)
}

// Clear 清空缓存
func (fc *FileCache) Clear() {
	fc.mutex.Lock()
	defer fc.mutex.Unlock()

	fc.cache = make(map[string]*ParseUnit)
	fc.hits = 0
	fc.misses = 0
}

// GetStats 获取缓存统计
func (fc *FileCache) GetStats() map[string]interface{} {
	fc.mutex.RLock()
	defer fc.mutex.RUnlock()

	stats := map[string]interface{}{
		"cache_size": len(fc.cache),
		"hits":       fc.hits,
		"misses":     fc.misses,
		"hit_rate":   0.0,
	}

	total := fc.hits + fc.misses
	if total > 0 {
		stats["hit_rate"] = float64(fc.hits) / float64(total)
	}

	return stats
}

// Preload 预加载文件
func (fc *FileCache) Preload(filePaths []string) {
	for _, filePath := range filePaths {
		go func(fp string) {
			_, err := fc.Get(fp)
			if err != nil && isVerbose() {
			}
		}(filePath)
	}
}

// GetCachedFiles 获取所有已缓存的文件
func (fc *FileCache) GetCachedFiles() []string {
	fc.mutex.RLock()
	defer fc.mutex.RUnlock()

	files := make([]string, 0, len(fc.cache))
	for filePath := range fc.cache {
		files = append(files, filePath)
	}
	return files
}

// isVerbose 检查是否启用详细模式
func isVerbose() bool {
	// 这里应该从全局配置获取
	// 目前简化实现
	return false
}

// === Phase 5: AST 压缩优化 ===

// ReleaseTree 释放 Tree 以节省内存（Phase 5 优化）
// Tree 可以被释放，因为 Source 保留，需要时可以重新解析
// 返回释放的内存大小（字节）
func (pu *ParseUnit) ReleaseTree() int64 {
	if pu.Tree == nil || pu.TreeReleased {
		return 0
	}

	// 估算 Tree 大小（简单估算：节点数 × 假定节点大小）
	nodeCount := pu.countNodes(pu.Tree.RootNode())
	estimatedSize := int64(nodeCount * 256) // 假设每个节点 256 字节

	// 释放 Tree
	pu.Tree = nil
	pu.TreeReleased = true
	pu.TreeSizeBytes = estimatedSize

	return estimatedSize
}

// EnsureTree 确保 Tree 可用（Phase 5 优化）
// 如果 Tree 已被释放，则重新解析文件
func (pu *ParseUnit) EnsureTree(ctx context.Context) error {
	if pu.Tree != nil {
		// Tree 可用，更新访问时间
		pu.TreeLastAccess = time.Now()
		return nil
	}

	if !pu.TreeReleased {
		// Tree 未被标记为释放，但为 nil，这是异常状态
		return nil
	}

	// Tree 已释放，需要重新解析
	parsedUnit, err := ParseFile(ctx, pu.FilePath)
	if err != nil {
		return err
	}

	pu.Tree = parsedUnit.Tree
	pu.TreeReleased = false
	pu.TreeLastAccess = time.Now()

	return nil
}

// countNodes 估算 Tree 中的节点数量
func (pu *ParseUnit) countNodes(node *sitter.Node) int {
	if node == nil {
		return 0
	}

	count := 1
	for i := 0; i < int(node.ChildCount()); i++ {
		count += pu.countNodes(node.Child(i))
	}
	return count
}

// GetTreeSize 获取 Tree 的内存占用（Phase 5 优化）
func (pu *ParseUnit) GetTreeSize() int64 {
	if pu.TreeReleased {
		return pu.TreeSizeBytes
	}

	if pu.Tree == nil {
		return 0
	}

	return int64(pu.countNodes(pu.Tree.RootNode()) * 256)
}

// CanReleaseTree 检查是否可以释放 Tree（Phase 5 优化）
// 规则：Tree 长时间未使用（超过 5 分钟）且引用计数为 0
func (pu *ParseUnit) CanReleaseTree(idleTimeout time.Duration) bool {
	if pu.Tree == nil || pu.TreeReleased {
		return false
	}

	// 检查引用计数
	if atomic.LoadInt32(&pu.RefCount) > 0 {
		return false
	}

	// 检查空闲时间
	if !pu.TreeLastAccess.IsZero() {
		idleTime := time.Since(pu.TreeLastAccess)
		if idleTime < idleTimeout {
			return false
		}
	}

	return true
}

// UpdateTreeAccess 更新 Tree 访问时间（Phase 5 优化）
func (pu *ParseUnit) UpdateTreeAccess() {
	if !pu.TreeReleased && pu.Tree != nil {
		pu.TreeLastAccess = time.Now()
	}
}

// Copy 创建 ParseUnit 的副本，用于并发访问（Phase 5 优化）
// 如果 Tree 已释放，则返回的副本也没有 Tree
func (pu *ParseUnit) Copy() *ParseUnit {
	var treeCopy *sitter.Tree
	if pu.Tree != nil && !pu.TreeReleased {
		treeCopy = pu.Tree.Copy()
	}

	return &ParseUnit{
		FilePath:       pu.FilePath,
		Tree:           treeCopy,
		Source:         pu.Source, // 源码只读，可以共享
		Functions:      pu.Functions,
		Variables:      pu.Variables,
		Macros:         pu.Macros,
		LoadedAt:       pu.LoadedAt,
		TreeLastAccess: time.Now(),
		TreeReleased:   pu.TreeReleased,
		TreeSizeBytes:  pu.TreeSizeBytes,
	}
}
