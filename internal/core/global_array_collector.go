package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode"

	"github.com/smacker/go-tree-sitter"
)

// 分片锁优化：使用多个分片减少锁竞争
const defaultShardCount = 16  // 默认分片数，可根据 CPU 核心数调整

// GlobalArrayCollector 全局常量数组收集器 (V12 分片锁优化版)
type GlobalArrayCollector struct {
	shards []*arrayShard
	shardCount int
}

// arrayShard 数组分片
type arrayShard struct {
	knownArrays map[string]bool
	arrayInfo   map[string]*ArrayInfo
	mu          sync.RWMutex
}

// ArrayInfo 数组信息
type ArrayInfo struct {
	Name           string
	IsConst        bool
	IsStatic       bool
	HasInitializer bool
	InitCount      int
	LiteralRatio   float64
	IsReadOnly     bool // 是否只读（使用分析）
	IsLookupTable  bool // 是否像查找表
}

// NewGlobalArrayCollector 创建全局数组收集器
func NewGlobalArrayCollector() *GlobalArrayCollector {
	return NewGlobalArrayCollectorWithShards(defaultShardCount)
}

// NewGlobalArrayCollectorWithShards 创建指定分片数的收集器
func NewGlobalArrayCollectorWithShards(shardCount int) *GlobalArrayCollector {
	c := &GlobalArrayCollector{
		shards:     make([]*arrayShard, shardCount),
		shardCount: shardCount,
	}

	for i := 0; i < shardCount; i++ {
		c.shards[i] = &arrayShard{
			knownArrays: make(map[string]bool),
			arrayInfo:   make(map[string]*ArrayInfo),
		}
	}

	return c
}

// getShard 根据名称获取对应的分片
func (c *GlobalArrayCollector) getShard(name string) *arrayShard {
	// 使用 FNV-1a 哈希算法选择分片
	hash := uint32(2166136261)
	for _, c := range name {
		hash ^= uint32(c)
		hash *= 16777619
	}
	return c.shards[int(hash)%c.shardCount]
}

// CollectArrays 预扫描所有文件，收集全局常量数组
func (c *GlobalArrayCollector) CollectArrays(ctx context.Context, files []string) error {
	// 清空所有分片
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.knownArrays = make(map[string]bool)
		shard.arrayInfo = make(map[string]*ArrayInfo)
		shard.mu.Unlock()
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errors := make([]error, 0)

	// 并发扫描所有文件
	for _, file := range files {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()

			// 解析文件
			unit, err := ParseFile(ctx, filePath)
			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("failed to parse %s: %w", filePath, err))
				mu.Unlock()
				return
			}

			// 收集该文件的全局数组信息
			arrays := c.collectGlobalArraysFromFile(unit)

			// 分析数组的使用模式
			c.analyzeArrayUsage(unit, arrays)

			// 合并到对应分片（减少锁竞争）
			for name, info := range arrays {
				shard := c.getShard(name)
				shard.mu.Lock()
				shard.arrayInfo[name] = info
				if c.isConstantArrayBySemantics(info) {
					shard.knownArrays[name] = true
				}
				shard.mu.Unlock()
			}
		}(file)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("collection completed with %d errors", len(errors))
	}

	return nil
}

// collectGlobalArraysFromFile 收集文件中的数组声明信息
func (c *GlobalArrayCollector) collectGlobalArraysFromFile(unit *ParsedUnit) map[string]*ArrayInfo {
	arrays := make(map[string]*ArrayInfo)
	root := unit.Root

	if root == nil {
		return arrays
	}

	// 创建分析上下文
	analyzeCtx := &analyzeContext{
		unit:   unit,
		root:   root,
		source: unit.Source,
	}

	// 遍历 AST 收集数组声明
	c.traverseAST(root, func(node *sitter.Node) bool {
		if node.Type() != "declaration" {
			return true
		}

		// 提取数组信息
		info := c.extractArrayInfo(analyzeCtx, node)
		if info != nil {
			arrays[info.Name] = info
		}

		return true
	})

	return arrays
}

// analyzeContext 分析上下文
type analyzeContext struct {
	unit   *ParsedUnit
	root   *sitter.Node
	source []byte
}

// getSourceText 获取节点的源代码文本
func (c *analyzeContext) getSourceText(node *sitter.Node) string {
	if node == nil {
		return ""
	}
	return string(c.source[node.StartByte():node.EndByte()])
}

// extractArrayInfo 从声明节点提取数组信息
func (c *GlobalArrayCollector) extractArrayInfo(ctx *analyzeContext, declNode *sitter.Node) *ArrayInfo {
	// 获取声明符
	declarator := declNode.ChildByFieldName("declarator")
	if declarator == nil || declarator.Type() != "array_declarator" {
		return nil
	}

	// 提取数组名
	arrayName := extractIdentifier(ctx, declarator)
	if arrayName == "" {
		return nil
	}

	// 获取完整的声明文本（遍历所有子节点）
	var fullDeclText strings.Builder
	for i := 0; i < int(declNode.ChildCount()); i++ {
		child := declNode.Child(i)
		if child != nil {
			fullDeclText.WriteString(ctx.getSourceText(child))
			fullDeclText.WriteString(" ")
		}
	}
	declTextStr := fullDeclText.String()

	// DEBUG: 输出声明文本
	//if arrayName == "crc_table" || arrayName == "crc_braid_table" {
	//	fmt.Printf("DEBUG: Extracting array '%s', fullDeclText: '%s'\n", arrayName, declTextStr)
	//}

	// 检查修饰符
	isConst := strings.Contains(declTextStr, "const")
	isStatic := strings.Contains(declTextStr, "static") || strings.Contains(declTextStr, "local")

	// 检查初始化列表
	value := declNode.ChildByFieldName("value")
	hasInit := value != nil && value.Type() == "initializer_list"

	initCount := 0
	literalCount := 0
	if hasInit {
		initCount, literalCount = c.analyzeInitializerList(value)
	}

	info := &ArrayInfo{
		Name:           arrayName,
		IsConst:        isConst,
		IsStatic:       isStatic,
		HasInitializer: hasInit,
		InitCount:      initCount,
		LiteralRatio:   0.0,
		IsReadOnly:     false,
		IsLookupTable:  false,
	}

	if initCount > 0 {
		info.LiteralRatio = float64(literalCount) / float64(initCount)
	}

	return info
}

// analyzeInitializerList 分析初始化列表
func (c *GlobalArrayCollector) analyzeInitializerList(initList *sitter.Node) (initCount, literalCount int) {
	for i := 0; i < int(initList.ChildCount()); i++ {
		child := initList.Child(i)
		if child == nil || child.Type() == "" || child.Type() == "," || child.Type() == "{" || child.Type() == "}" {
			continue
		}
		initCount++
		if isLiteral(child) {
			literalCount++
		}
	}
	return
}

// isLiteral 判断是否为字面量
func isLiteral(node *sitter.Node) bool {
	switch node.Type() {
	case "number_literal", "string_literal", "true", "false", "char_literal":
		return true
	}
	return false
}

// analyzeArrayUsage 分析数组的使用模式
func (c *GlobalArrayCollector) analyzeArrayUsage(unit *ParsedUnit, arrays map[string]*ArrayInfo) {
	// 构建写入操作的统计
	writeOps := make(map[string]int)
	readOps := make(map[string]int)

	source := unit.Source

	// 遍历所有表达式，追踪数组的读写操作
	c.traverseAST(unit.Root, func(node *sitter.Node) bool {
		// 检查赋值表达式
		if node.Type() == "assignment_expression" {
			left := node.ChildByFieldName("left")
			if left != nil && (left.Type() == "subscript_expression" || left.Type() == "call_expression") {
				// 提取数组名
				arrayName := extractFromArrayAccessWithSource(left, source)
				if arrayName != "" {
					writeOps[arrayName]++
				}
			}
		}

		// 检查数组读取
		if node.Type() == "subscript_expression" {
			// 确保不是在赋值左侧
			parent := node.Parent()
			if parent == nil || parent.Type() != "assignment_expression" || parent.ChildByFieldName("left") != node {
				arrayName := extractFromArrayAccessWithSource(node, source)
				if arrayName != "" {
					readOps[arrayName]++
				}
			}
		}

		return true
	})

	// 更新数组信息
	for name, info := range arrays {
		writes := writeOps[name]
		reads := readOps[name]

		// 只读判断：没有写入操作或写入很少
		info.IsReadOnly = writes == 0 || (reads > 0 && writes < reads/10)

		// 查找表判断：主要是读取操作，且有很多次访问
		info.IsLookupTable = reads > 5 && (reads > writes*2 || writes == 0)
	}
}

// extractFromArrayAccessWithSource 从数组访问表达式中提取数组名（带 source）
func extractFromArrayAccessWithSource(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}

	// 处理 subscript_expression (arr[i])
	if node.Type() == "subscript_expression" {
		object := node.ChildByFieldName("object")
		if object != nil && object.Type() == "identifier" {
			// 使用 source 获取文本
			start := object.StartByte()
			end := object.EndByte()
			if end > start && int(end) <= len(source) {
				return string(source[start:end])
			}
		}
	}

	return ""
}

// extractFromArrayAccess 从数组访问表达式中提取数组名
func extractFromArrayAccess(node *sitter.Node) string {
	if node == nil {
		return ""
	}

	// 处理 subscript_expression (arr[i])
	if node.Type() == "subscript_expression" {
		object := node.ChildByFieldName("object")
		if object != nil && object.Type() == "identifier" {
			// identifier 节点的内容就是其字节范围
			// 但我们需要源代码来获取文本，这里返回空字符串
			// 实际使用时需要通过上下文获取
			return ""
		}
	}

	return ""
}

// 辅助函数：获取节点的文本内容（需要 source）
func getNodeText(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}
	start := node.StartByte()
	end := node.EndByte()
	return string(source[start:end])
}

// extractIdentifier 从节点提取标识符
func extractIdentifier(ctx *analyzeContext, node *sitter.Node) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Type() == "identifier" {
			return ctx.getSourceText(child)
		}
	}
	return ""
}

// isConstantArrayBySemantics 基于语义判断是否为常量数组
func (c *GlobalArrayCollector) isConstantArrayBySemantics(info *ArrayInfo) bool {
	return c.calculateScore(info) >= 0.4
}

// calculateScore 计算数组的常量可能性评分
func (c *GlobalArrayCollector) calculateScore(info *ArrayInfo) float64 {
	score := 0.0

	// 1. 使用特征 (权重: 50%) - 使用模式是最可靠的语义特征
	if info.IsReadOnly {
		score += 0.40
	}
	if info.IsLookupTable {
		score += 0.10
	}

	// 2. 声明特征 (权重: 30%) - 可能受宏影响，降低权重
	if info.IsConst {
		score += 0.30
	} else if info.IsStatic {
		score += 0.15
	}

	// 3. 初始化特征 (权重: 15%)
	if info.HasInitializer {
		if info.InitCount > 10 {
			score += 0.10
		}
		if info.LiteralRatio > 0.8 {
			score += 0.05
		}
	}

	// 4. 命名约定推断 (权重: 5%)
	if c.usesConstantNamingConvention(info.Name) {
		score += 0.05
	}

	return score
}

// usesConstantNamingConvention 基于命名约定推断是否为常量
// 不使用硬编码列表，而是分析命名模式
func (c *GlobalArrayCollector) usesConstantNamingConvention(name string) bool {
	// 特征1：全大写（常量命名约定）
	if strings.ToUpper(name) == name && len(name) > 1 {
		return true
	}

	// 特征2：下划线分隔且不包含小写动词
	// 常量通常使用下划线分隔，且不包含动词
	if strings.Contains(name, "_") {
		// 检查是否包含动词（非常量的特征）
		verbs := []string{"get", "set", "update", "compute", "calculate", "process", "handle"}
		nameLower := strings.ToLower(name)
		hasVerb := false
		for _, verb := range verbs {
			if strings.Contains(nameLower, verb) {
				hasVerb = true
				break
			}
		}
		if !hasVerb {
			return true
		}
	}

	// 特征3：短名称且全大写（如 CRC, LUT）
	if len(name) <= 4 && strings.ToUpper(name) == name {
		return true
	}

	return false
}

// traverseAST 遍历 AST 树
func (c *GlobalArrayCollector) traverseAST(node *sitter.Node, visitor func(*sitter.Node) bool) {
	if node == nil {
		return
	}

	if !visitor(node) {
		return
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		c.traverseAST(child, visitor)
	}
}

// GetKnownArrays 获取已识别的全局数组列表（分片聚合）
func (c *GlobalArrayCollector) GetKnownArrays() map[string]bool {
	result := make(map[string]bool)

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for k, v := range shard.knownArrays {
			result[k] = v
		}
		shard.mu.RUnlock()
	}

	return result
}

// GetArrayInfo 获取数组详细信息（分片聚合）
func (c *GlobalArrayCollector) GetArrayInfo() map[string]*ArrayInfo {
	result := make(map[string]*ArrayInfo)

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for k, v := range shard.arrayInfo {
			result[k] = v
		}
		shard.mu.RUnlock()
	}

	return result
}

// IsKnownArray 检查是否为已知全局数组（单分片查询）
func (c *GlobalArrayCollector) IsKnownArray(arrayName string) bool {
	shard := c.getShard(arrayName)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	return shard.knownArrays[arrayName]
}

// GetArrayCount 获取已识别的数组数量（分片聚合）
func (c *GlobalArrayCollector) GetArrayCount() int {
	count := 0

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		count += len(shard.knownArrays)
		shard.mu.RUnlock()
	}

	return count
}

// 辅助函数：检查是否包含动词
func containsVerb(name string) bool {
	verbs := []string{"get", "set", "put", "add", "remove", "delete", "update",
		"compute", "calculate", "process", "handle", "parse", "format",
		"convert", "transform", "validate", "check", "find", "search"}
	nameLower := strings.ToLower(name)
	for _, verb := range verbs {
		if strings.Contains(nameLower, verb) {
			return true
		}
	}
	return false
}

// 辅助函数：检查是否主要是大写字母
func isMostlyUppercase(name string) bool {
	if len(name) == 0 {
		return false
	}
	upperCount := 0
	for _, r := range name {
		if unicode.IsUpper(r) {
			upperCount++
		}
	}
	return upperCount > len(name)*2/3
}
