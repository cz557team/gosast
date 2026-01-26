package core

import (
	"context"
	"fmt"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
)

// 分片锁优化：使用多个分片减少锁竞争
const defaultStructShardCount = 16  // 默认分片数，可根据 CPU 核心数调整

// StructInfo 结构体信息 (V14 分片锁优化版)
type StructInfo struct {
	Name         string
	Fields       map[string]*StructFieldInfo
	FilePath     string
	Line         int
}

// StructFieldInfo 结构体字段信息
type StructFieldInfo struct {
	Name         string
	Type         string
	IsPointer    bool
	IsArray      bool
	ArraySize    string
	IsStaticArray bool // 是否为数组类型 (array_declarator)
}

// GlobalStructCollector 全局结构体收集器 (V14 分片锁优化版)
// 收集所有文件（包括头文件）中的结构体定义，支持跨文件共享
type GlobalStructCollector struct {
	shards     []*structShard
	shardCount int
}

// structShard 结构体分片
type structShard struct {
	structs map[string]*StructInfo
	mu      sync.RWMutex
}

// NewGlobalStructCollector 创建全局结构体收集器
func NewGlobalStructCollector() *GlobalStructCollector {
	return NewGlobalStructCollectorWithShards(defaultStructShardCount)
}

// NewGlobalStructCollectorWithShards 创建指定分片数的收集器
func NewGlobalStructCollectorWithShards(shardCount int) *GlobalStructCollector {
	c := &GlobalStructCollector{
		shards:     make([]*structShard, shardCount),
		shardCount: shardCount,
	}

	for i := 0; i < shardCount; i++ {
		c.shards[i] = &structShard{
			structs: make(map[string]*StructInfo),
		}
	}

	return c
}

// getShard 根据名称获取对应的分片
func (c *GlobalStructCollector) getShard(name string) *structShard {
	// 使用 FNV-1a 哈希算法选择分片
	hash := uint32(2166136261)
	for _, c := range name {
		hash ^= uint32(c)
		hash *= 16777619
	}
	return c.shards[int(hash)%c.shardCount]
}

// CollectStructs 预扫描所有文件，收集结构体定义（分片锁优化版）
func (c *GlobalStructCollector) CollectStructs(ctx context.Context, files []string) error {
	// 清空所有分片
	for _, shard := range c.shards {
		shard.mu.Lock()
		shard.structs = make(map[string]*StructInfo)
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

			// 收集该文件的结构体定义
			structs := c.collectStructsFromFile(unit)

			// 合并到对应分片（减少锁竞争）
			for name, info := range structs {
				shard := c.getShard(name)
				shard.mu.Lock()
				// 如果结构体已存在，保留字段更完整的版本
				if existing, ok := shard.structs[name]; ok {
					if len(info.Fields) > len(existing.Fields) {
						shard.structs[name] = info
					}
				} else {
					shard.structs[name] = info
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

// collectStructsFromFile 收集文件中的结构体定义
func (c *GlobalStructCollector) collectStructsFromFile(unit *ParsedUnit) map[string]*StructInfo {
	structs := make(map[string]*StructInfo)
	root := unit.Root

	if root == nil {
		return structs
	}

	// 遍历 AST 收集结构体定义
	c.traverseAST(root, func(node *sitter.Node) bool {
		// 查找 struct_specifier 节点
		if node.Type() != "struct_specifier" {
			return true
		}

		// 提取结构体信息
		info := c.extractStructInfo(unit, node)
		if info != nil && info.Name != "" {
			structs[info.Name] = info
		}

		return true
	})

	return structs
}

// extractStructInfo 从 struct_specifier 节点提取结构体信息
func (c *GlobalStructCollector) extractStructInfo(unit *ParsedUnit, structNode *sitter.Node) *StructInfo {
	// 获取结构体名
	var structName string
	for i := 0; i < int(structNode.ChildCount()); i++ {
		child := structNode.Child(i)
		if child.Type() == "type_identifier" {
			structName = unit.getSourceText(child)
			break
		}
	}

	// 跳过匿名结构体（无法通过名称引用）
	if structName == "" {
		return nil
	}

	info := &StructInfo{
		Name:   structName,
		Fields: make(map[string]*StructFieldInfo),
		FilePath: unit.FilePath,
		Line:   int(structNode.StartPoint().Row) + 1,
	}

	// 获取结构体体
	body := structNode.ChildByFieldName("body")
	if body != nil {
		c.analyzeStructFields(unit, body, info)
	}

	return info
}

// analyzeStructFields 分析结构体字段
func (c *GlobalStructCollector) analyzeStructFields(unit *ParsedUnit, bodyNode *sitter.Node, structInfo *StructInfo) {
	for i := 0; i < int(bodyNode.ChildCount()); i++ {
		child := bodyNode.Child(i)
		if child.Type() == "field_declaration" {
			fieldInfo := c.parseFieldDeclaration(unit, child)
			if fieldInfo != nil {
				structInfo.Fields[fieldInfo.Name] = fieldInfo
			}
		}
	}
}

// parseFieldDeclaration 解析字段声明
func (c *GlobalStructCollector) parseFieldDeclaration(unit *ParsedUnit, fieldNode *sitter.Node) *StructFieldInfo {
	var fieldName string
	var fieldType string
	var isPointer bool
	var isArray bool
	var isStaticArray bool
	var arraySize string

	// DEBUG: 输出字段声明原文
	fieldText := unit.getSourceText(fieldNode)
	if len(fieldText) > 0 && len(fieldText) < 200 {
// 0 fmt.Printf("DEBUG V13-FIELD: %s\n", fieldText)
	}

	// 获取类型
	typeNode := fieldNode.ChildByFieldName("type")
	if typeNode != nil {
		fieldType = unit.getSourceText(typeNode)
		if strings.Contains(fieldType, "*") {
			isPointer = true
		}
	}

	// 获取声明符
	declarator := fieldNode.ChildByFieldName("declarator")
	if declarator != nil {
		if declarator.Type() == "identifier" {
			fieldName = unit.getSourceText(declarator)
		} else if declarator.Type() == "pointer_declarator" {
			isPointer = true
			// 查找标识符
			for j := 0; j < int(declarator.ChildCount()); j++ {
				subChild := declarator.Child(j)
				if subChild.Type() == "identifier" {
					fieldName = unit.getSourceText(subChild)
					break
				}
			}
		} else if declarator.Type() == "array_declarator" {
			isArray = true
			isStaticArray = true
			// 获取数组名和大小
			// array_declarator 的子节点顺序: [field_identifier, [, identifier/number_literal, ]]

			for j := 0; j < int(declarator.ChildCount()); j++ {
				subChild := declarator.Child(j)
				if subChild == nil || subChild.Type() == "" || subChild.Type() == "[" || subChild.Type() == "]" {
					continue
				}
				// 第一个 field_identifier 或 identifier 是数组名
				if fieldName == "" && (subChild.Type() == "field_identifier" || subChild.Type() == "identifier") {
					fieldName = unit.getSourceText(subChild)
				} else if subChild.Type() == "number_literal" {
					arraySize = unit.getSourceText(subChild)
				} else if subChild.Type() == "identifier" && fieldName != "" {
					// 后续 identifier 可能是宏定义的数组大小（如 MAXWIN）
					arraySize = unit.getSourceText(subChild)
				}
			}
		}
	}

	if fieldName == "" {
		return nil
	}

	// DEBUG: 输出解析的字段信息
	if fieldName == "out" || fieldName == "in" || fieldName == "bitbuf" || fieldName == "bitcnt" {
		// fmt.Printf("DEBUG V13-PARSE: fieldName=%s, Type=%s, isArray=%v, isStaticArray=%v, ArraySize='%s'\n",
		// 	fieldName, fieldType, isArray, isStaticArray, arraySize)
	}

	return &StructFieldInfo{
		Name:         fieldName,
		Type:         fieldType,
		IsPointer:    isPointer,
		IsArray:      isArray,
		IsStaticArray: isStaticArray,
		ArraySize:    arraySize,
	}
}

// traverseAST 遍历 AST 树
func (c *GlobalStructCollector) traverseAST(node *sitter.Node, visitor func(*sitter.Node) bool) {
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

// GetStructs 获取所有结构体信息（分片聚合）
func (c *GlobalStructCollector) GetStructs() map[string]*StructInfo {
	result := make(map[string]*StructInfo)

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for k, v := range shard.structs {
			result[k] = v
		}
		shard.mu.RUnlock()
	}

	return result
}

// GetStruct 获取指定名称的结构体信息（单分片查询）
func (c *GlobalStructCollector) GetStruct(structName string) *StructInfo {
	shard := c.getShard(structName)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	return shard.structs[structName]
}

// GetStructCount 获取已识别的结构体数量（分片聚合）
func (c *GlobalStructCollector) GetStructCount() int {
	count := 0

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		count += len(shard.structs)
		shard.mu.RUnlock()
	}

	return count
}

// GetFieldInfo 获取指定结构体的字段信息（单分片查询）
func (c *GlobalStructCollector) GetFieldInfo(structName, fieldName string) *StructFieldInfo {
	shard := c.getShard(structName)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	if structInfo, ok := shard.structs[structName]; ok {
		return structInfo.Fields[fieldName]
	}
	return nil
}

// getSourceText 获取节点的源代码文本
func (unit *ParsedUnit) getSourceText(node *sitter.Node) string {
	if node == nil {
		return ""
	}
	return string(unit.Source[node.StartByte():node.EndByte()])
}
