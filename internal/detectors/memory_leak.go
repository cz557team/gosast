package detectors

import (
	"fmt"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// MemoryLeakDetector 内存泄漏检测器 (CWE-401)
// 检测动态分配的内存未正确释放的情况
// 主要场景：
// 1. new/malloc 分配后没有对应的 delete/free
// 2. 异常路径导致资源未释放
// 3. 控制流中存在未释放资源的返回路径
type MemoryLeakDetector struct {
	*core.BaseDetector
	// 资源分配追踪
	allocations    map[*sitter.Node]*AllocationInfo
	deallocations  map[string][]*sitter.Node // 变量名 -> delete/free语句列表
	exceptionPaths map[*sitter.Node]bool     // 可能抛出异常的节点
	mutex          sync.RWMutex
}

// AllocationInfo 内存分配信息
type AllocationInfo struct {
	PointerName string       // 指针变量名
	AllocNode   *sitter.Node // new/malloc 语句节点
	AllocType   string       // "new", "new[]", "malloc", "calloc"
	LineNumber  int
	HasDelete   bool // 是否有对应的 delete
}

// NewMemoryLeakDetector 创建内存泄漏检测器
func NewMemoryLeakDetector() *MemoryLeakDetector {
	return &MemoryLeakDetector{
		BaseDetector: core.NewBaseDetector(
			"Memory Leak Detector",
			"Detects missing release of dynamically allocated memory (CWE-401)",
		),
		allocations:    make(map[*sitter.Node]*AllocationInfo),
		deallocations:  make(map[string][]*sitter.Node),
		exceptionPaths: make(map[*sitter.Node]bool),
	}
}

// Name 返回检测器名称
func (d *MemoryLeakDetector) Name() string {
	return "Memory Leak Detector"
}

// Run 运行检测器
func (d *MemoryLeakDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// 清空之前的数据
	d.allocations = make(map[*sitter.Node]*AllocationInfo)
	d.deallocations = make(map[string][]*sitter.Node)
	d.exceptionPaths = make(map[*sitter.Node]bool)

	root := ctx.Unit.Root
	source := ctx.Unit.Source

	// 第1步：收集所有内存分配和释放操作
	d.collectMemoryOperations(ctx, root, source)

	// fmt.Printf("[DEBUG] Found %d allocations and %d unique deallocations\n",
	// 	len(d.allocations), len(d.deallocations))

	// 第2步：分析控制流，检查异常路径
	d.analyzeExceptionPaths(ctx, root, source)

	// 第3步：检测内存泄漏
	vulns := d.detectMemoryLeaks(ctx, source)

	return vulns, nil
}

// collectMemoryOperations 收集内存分配和释放操作
func (d *MemoryLeakDetector) collectMemoryOperations(ctx *core.AnalysisContext, root *sitter.Node, source []byte) {
	visited := make(map[*sitter.Node]bool)

	var collectFunc func(*sitter.Node)
	collectFunc = func(node *sitter.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true

		// 检查是否是内存分配操作
		if d.isMemoryAllocation(node, source) {
			pointerName := d.extractPointerName(node, source)
			// fmt.Printf("[DEBUG] Found allocation: pointer='%s', content='%s'\n",
			// 	pointerName, string(node.Content(source)))
			if pointerName != "" {
				d.allocations[node] = &AllocationInfo{
					PointerName: pointerName,
					AllocNode:   node,
					AllocType:   d.getAllocType(node, source),
					LineNumber:  int(node.StartPoint().Row) + 1,
				}
			}
		}

		// 检查是否是内存释放操作
		if d.isMemoryDeallocation(node, source) {
			pointerName := d.extractDeletedPointer(node, source)
			// fmt.Printf("[DEBUG] Found deallocation: pointer='%s', content='%s'\n",
			// 	pointerName, string(node.Content(source)))
			if pointerName != "" {
				d.deallocations[pointerName] = append(d.deallocations[pointerName], node)
			}
		}

		// 递归处理子节点
		for i := 0; i < int(node.ChildCount()); i++ {
			collectFunc(node.Child(i))
		}
	}

	collectFunc(root)
}

// isMemoryAllocation 检查是否是内存分配操作
func (d *MemoryLeakDetector) isMemoryAllocation(node *sitter.Node, source []byte) bool {
	content := string(node.Content(source))

	// C++ new/new[] 操作
	if strings.Contains(content, "new ") || strings.Contains(content, "new[") {
		return true
	}

	// C malloc/calloc/realloc 操作
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "identifier" {
				funcName := string(child.Content(source))
				if funcName == "malloc" || funcName == "calloc" || funcName == "realloc" ||
					funcName == "kmalloc" || funcName == "vmalloc" {
					return true
				}
			}
		}
	}

	return false
}

// isMemoryDeallocation 检查是否是内存释放操作
func (d *MemoryLeakDetector) isMemoryDeallocation(node *sitter.Node, source []byte) bool {
	content := string(node.Content(source))

	// C++ delete/delete[] 操作
	if strings.HasPrefix(content, "delete ") || strings.HasPrefix(content, "delete[") {
		return true
	}

	// C free 操作
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "identifier" {
				funcName := string(child.Content(source))
				if funcName == "free" || funcName == "kfree" || funcName == "vfree" {
					return true
				}
			}
		}
	}

	return false
}

// deepSearchIdentifier 深度搜索节点中的标识符
func (d *MemoryLeakDetector) deepSearchIdentifier(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}

	// 检查当前节点是否是 identifier
	if node.Type() == "identifier" {
		potentialName := string(node.Content(source))
		// 排除一些常见的非变量名的标识符
		if potentialName != "new" && potentialName != "delete" &&
			potentialName != "malloc" && potentialName != "free" &&
			potentialName != "calloc" && potentialName != "realloc" &&
			potentialName != "std" && potentialName != "auto" &&
			potentialName != "sizeof" {
			// fmt.Printf("[DEBUG]       deepSearch found identifier: '%s'\n", potentialName)
			return potentialName
		}
	}

	// 递归搜索所有子节点
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			// 跳过一些明显的非变量节点
			if child.Type() == "=" || child.Type() == ";" ||
				child.Type() == "," || child.Type() == "(" ||
				child.Type() == ")" {
				continue
			}
			if result := d.deepSearchIdentifier(child, source); result != "" {
				return result
			}
		}
	}

	return ""
}

// extractPointerName 从分配语句中提取指针变量名
func (d *MemoryLeakDetector) extractPointerName(node *sitter.Node, source []byte) string {
	// 对于 "int *ptr = new int;" 这种声明语句
	// new 操作节点的父节点应该是某个表达式
	// 我们需要向上查找包含指针变量名的节点

	current := node
	maxDepth := 5 // 限制向上查找的深度，避免无限循环

	// fmt.Printf("[DEBUG] extractPointerName: starting from node type=%s, content='%s'\n",
	// 	node.Type(), string(node.Content(source)))

	for depth := 0; depth < maxDepth && current != nil; depth++ {
		parent := current.Parent()
		if parent == nil {
			break
		}

		// fmt.Printf("[DEBUG]   Depth %d: parent type=%s, content='%s'\n",
		// 	depth, parent.Type(), string(parent.Content(source)))

		// 如果父节点是声明语句，在其中查找标识符
		if parent.Type() == "declaration" || parent.Type() == "init_declarator" ||
			parent.Type() == "assignment_expression" {
			// 深度搜索所有子节点（包括嵌套的 pointer_declarator）
			pointerName := d.deepSearchIdentifier(parent, source)
			if pointerName != "" {
				// fmt.Printf("[DEBUG]     Returning pointer name: '%s'\n", pointerName)
				return pointerName
			}
		}

		current = parent
	}

	// fmt.Printf("[DEBUG]   No pointer name found\n")
	return ""
}

// extractDeletedPointer 从delete语句中提取指针变量名
func (d *MemoryLeakDetector) extractDeletedPointer(node *sitter.Node, source []byte) string {
	content := string(node.Content(source))

	// 对于 delete 操作: "delete ptr;"
	if strings.HasPrefix(content, "delete") {
		// 提取 delete 后面的标识符
		parts := strings.Fields(content)
		if len(parts) >= 2 {
			// 去掉 "delete" 或 "delete[]" 后的部分
			ptrName := parts[len(parts)-1]
			// 去掉可能的分号
			ptrName = strings.TrimSuffix(ptrName, ";")
			return ptrName
		}
	}

	// 对于 free(ptr) 调用
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "argument_list" {
				// 第一个参数是指针
				if child.ChildCount() > 0 {
					arg := child.Child(0)
					if arg != nil && arg.Type() == "identifier" {
						return string(arg.Content(source))
					}
				}
			}
		}
	}

	return ""
}

// getAllocType 获取分配类型
func (d *MemoryLeakDetector) getAllocType(node *sitter.Node, source []byte) string {
	content := string(node.Content(source))

	if strings.Contains(content, "new[") {
		return "new[]"
	} else if strings.Contains(content, "new ") {
		return "new"
	}

	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "identifier" {
				return string(child.Content(source))
			}
		}
	}

	return "unknown"
}

// analyzeExceptionPaths 分析异常路径
func (d *MemoryLeakDetector) analyzeExceptionPaths(ctx *core.AnalysisContext, root *sitter.Node, source []byte) {
	visited := make(map[*sitter.Node]bool)

	var analyzeFunc func(*sitter.Node)
	analyzeFunc = func(node *sitter.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true

		// 检查是否是 throw 语句
		if node.Type() == "throw_statement" || node.Type() == "expression_statement" {
			content := string(node.Content(source))
			if strings.Contains(content, "throw") {
				// 标记从函数入口到这里的路径可能存在异常
				d.markExceptionPathToFunction(node)
			}
		}

		// 递归处理子节点
		for i := 0; i < int(node.ChildCount()); i++ {
			analyzeFunc(node.Child(i))
		}
	}

	analyzeFunc(root)
}

// markExceptionPathToFunction 标记到函数入口的异常路径
func (d *MemoryLeakDetector) markExceptionPathToFunction(throwNode *sitter.Node) {
	// 向上遍历到函数定义
	current := throwNode
	for current != nil {
		if current.Type() == "function_definition" || current.Type() == "compound_statement" {
			d.exceptionPaths[current] = true
			break
		}
		current = current.Parent()
	}
}

// detectMemoryLeaks 检测内存泄漏
func (d *MemoryLeakDetector) detectMemoryLeaks(ctx *core.AnalysisContext, source []byte) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 检查每个分配操作
	for allocNode, allocInfo := range d.allocations {
		pointerName := allocInfo.PointerName

		// 检查是否有对应的释放操作
		deallocs := d.deallocations[pointerName]
		if len(deallocs) == 0 {
			// 没有任何释放操作 - 肯定泄漏
			vuln := d.createLeakVulnerability(allocInfo, source,
				fmt.Sprintf("Memory allocated with %s is never released",
					allocInfo.AllocType))
			vulns = append(vulns, *vuln)
		} else {
			// 有释放操作，检查控制流是否可能被跳过
			if !d.isAllPathsCovered(allocNode, deallocs, source) {
				vuln := d.createLeakVulnerability(allocInfo, source,
					fmt.Sprintf("Memory allocated with %s may not be released on all execution paths",
						allocInfo.AllocType))
				vulns = append(vulns, *vuln)
			}
		}
	}

	return vulns
}

// isAllPathsCovered 检查所有路径是否都有释放操作
func (d *MemoryLeakDetector) isAllPathsCovered(allocNode *sitter.Node, deallocs []*sitter.Node, source []byte) bool {
	// 简化版本：检查分配和释放是否在同一个基本块中
	// 如果在同一作用域内，假设路径覆盖
	// TODO: 更精确的控制流分析

	allocLine := int(allocNode.StartPoint().Row) + 1

	// 检查是否有任何 delete 在分配之后
	for _, dealloc := range deallocs {
		deallocLine := int(dealloc.StartPoint().Row) + 1
		if deallocLine > allocLine {
			// 检查是否在异常路径中
			if d.isOnExceptionPath(allocNode, dealloc, source) {
				return false
			}
			return true
		}
	}

	return false
}

// isOnExceptionPath 检查分配和释放之间是否有异常路径
func (d *MemoryLeakDetector) isOnExceptionPath(allocNode, deallocNode *sitter.Node, source []byte) bool {
	// 简化版本：检查分配和释放之间是否有 throw 语句
	current := allocNode
	targetLine := int(deallocNode.StartPoint().Row)

	for current != nil && int(current.StartPoint().Row) < targetLine {
		content := string(current.Content(source))
		if strings.Contains(content, "throw") {
			return true
		}
		current = current.Parent()
		if current != nil && current.Type() == "function_definition" {
			break
		}
		if current != nil {
			// 移动到下一个兄弟节点
			next := current.NextSibling()
			if next != nil {
				current = next
			} else {
				break
			}
		} else {
			break
		}
	}

	return false
}

// createLeakVulnerability 创建内存泄漏漏洞报告
func (d *MemoryLeakDetector) createLeakVulnerability(allocInfo *AllocationInfo, source []byte, message string) *core.DetectorVulnerability {
	return &core.DetectorVulnerability{
		Type: "CWE-401: Memory Leak",
		Message: fmt.Sprintf("%s. Pointer '%s' allocated at line %d is not properly released.",
			message, allocInfo.PointerName, allocInfo.LineNumber),
		Severity:   "medium",
		Confidence: "medium",
		Line:       allocInfo.LineNumber,
		Column:     0,
	}
}
