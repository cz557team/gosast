package detectors

import (
	"fmt"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// AtomicityViolationDetector 原子性违规检测器 (CWE-360)
// 检测检查-使用（check-then-act）模式中的原子性违规
// 主要场景：
// 1. 对 atomic 变量的分离 load 和 store 操作
// 2. 检查条件和使用之间存在时间窗口
// 3. 应该使用 CAS 操作但没有使用的情况
type AtomicityViolationDetector struct {
	*core.BaseDetector
	atomicVars    map[string]string  // 变量名 -> atomic类型
	checkPatterns []*CheckActPattern // 检查-使用模式
	mutex         sync.RWMutex
}

// CheckActPattern 检查-使用模式
type CheckActPattern struct {
	CheckNode    *sitter.Node // 检查节点（如 if 语句）
	ActNode      *sitter.Node // 使用节点（如赋值/操作）
	VariableName string       // 涉及的变量名
	CheckLine    int          // 检查行号
	ActLine      int          // 使用行号
	HasDelay     bool         // 是否有明显的延迟（如 sleep）
	IsAtomic     bool         // 涉及的变量是否是 atomic 类型
}

// NewAtomicityViolationDetector 创建原子性违规检测器
func NewAtomicityViolationDetector() *AtomicityViolationDetector {
	return &AtomicityViolationDetector{
		BaseDetector: core.NewBaseDetector(
			"Atomicity Violation Detector",
			"Detects check-then-act atomicity violations (CWE-360)",
		),
		atomicVars:    make(map[string]string),
		checkPatterns: make([]*CheckActPattern, 0),
	}
}

// Name 返回检测器名称
func (d *AtomicityViolationDetector) Name() string {
	return "Atomicity Violation Detector"
}

// Run 运行检测器
func (d *AtomicityViolationDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// 清空之前的数据
	d.atomicVars = make(map[string]string)
	d.checkPatterns = make([]*CheckActPattern, 0)

	root := ctx.Unit.Root
	source := ctx.Unit.Source

	// 第1步：收集 atomic 变量声明
	d.collectAtomicVariables(ctx, root, source)

	// 第2步：查找检查-使用模式
	d.findCheckActPatterns(ctx, root, source)

	// 第3步：检测原子性违规
	vulns := d.detectAtomicityViolations(ctx, source)

	return vulns, nil
}

// collectAtomicVariables 收集 atomic 变量声明
func (d *AtomicityViolationDetector) collectAtomicVariables(ctx *core.AnalysisContext, root *sitter.Node, source []byte) {
	visited := make(map[*sitter.Node]bool)

	var collectFunc func(*sitter.Node)
	collectFunc = func(node *sitter.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true

		// 检查是否是声明语句
		if node.Type() == "declaration" {
			content := string(node.Content(source))

			// 检查是否包含 atomic 类型
			if strings.Contains(content, "atomic<") || strings.Contains(content, "atomic ") {
				// 提取变量名
				varName := d.extractVariableNameFromDeclaration(node, source)
				if varName != "" {
					// 提取完整的 atomic 类型
					atomicType := d.extractAtomicType(content)
					d.atomicVars[varName] = atomicType
				}
			}
		}

		// 递归处理子节点
		for i := 0; i < int(node.ChildCount()); i++ {
			collectFunc(node.Child(i))
		}
	}

	collectFunc(root)
}

// extractVariableNameFromDeclaration 从声明中提取变量名
func (d *AtomicityViolationDetector) extractVariableNameFromDeclaration(node *sitter.Node, source []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		// 查找声明符节点
		if child.Type() == "init_declarator" || child.Type() == "declarator" {
			// 在声明符中查找标识符
			for j := 0; j < int(child.ChildCount()); j++ {
				grandchild := child.Child(j)
				if grandchild != nil && grandchild.Type() == "identifier" {
					name := string(grandchild.Content(source))
					// 过滤掉类型名
					if name != "atomic" && !strings.HasPrefix(name, "std::") {
						return name
					}
				}
			}
		}
	}
	return ""
}

// extractAtomicType 提取 atomic 类型
func (d *AtomicityViolationDetector) extractAtomicType(content string) string {
	// 简化版本：提取完整的 atomic 类型声明
	if strings.Contains(content, "atomic<") {
		// atomic<Type>
		start := strings.Index(content, "atomic<")
		end := strings.Index(content[start:], ">")
		if end != -1 {
			return content[start : start+end+1]
		}
	}
	return "atomic"
}

// findCheckActPatterns 查找检查-使用模式
func (d *AtomicityViolationDetector) findCheckActPatterns(ctx *core.AnalysisContext, root *sitter.Node, source []byte) {
	visited := make(map[*sitter.Node]bool)

	var findFunc func(*sitter.Node)
	findFunc = func(node *sitter.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true

		// 检查是否是 if 语句
		if node.Type() == "if_statement" {
			pattern := d.analyzeIfStatement(node, source)
			if pattern != nil {
				d.checkPatterns = append(d.checkPatterns, pattern)
			}
		}

		// 递归处理子节点
		for i := 0; i < int(node.ChildCount()); i++ {
			findFunc(node.Child(i))
		}
	}

	findFunc(root)
}

// analyzeIfStatement 分析 if 语句，查找检查-使用模式
func (d *AtomicityViolationDetector) analyzeIfStatement(node *sitter.Node, source []byte) *CheckActPattern {
	// if_statement 的结构：
	// Child 0: if
	// Child 1: condition (条件表达式)
	// Child 2: consequence (then 分支，通常是 compound_statement)
	// Child 3: alternative (else 分支，可选)

	if node.ChildCount() < 3 {
		return nil
	}

	// 获取条件表达式
	condition := node.Child(1)
	if condition == nil {
		return nil
	}

	// 如果是 condition_clause，需要深入到内部表达式
	actualCondition := condition
	if condition.Type() == "condition_clause" {
		// condition_clause 的结构：
		// Child 0: (
		// Child 1: 实际的条件表达式
		// Child 2: )
		if condition.ChildCount() > 1 {
			actualCondition = condition.Child(1) // 获取第二个子节点
		}
	}

	// 从条件中提取变量名
	varName := d.extractVariableFromCondition(actualCondition, source)
	if varName == "" {
		return nil
	}

	// 检查变量是否是 atomic 类型
	isAtomic := d.atomicVars[varName] != ""

	// 获取 then 分支
	consequence := node.Child(2)
	if consequence == nil || consequence.Type() != "compound_statement" {
		return nil
	}

	// 在 then 分支中查找对该变量的使用
	actNode, actLine, hasDelay := d.findVariableUsageInBlock(consequence, varName, source)
	if actNode == nil {
		return nil
	}

	return &CheckActPattern{
		CheckNode:    node,
		ActNode:      actNode,
		VariableName: varName,
		CheckLine:    int(node.StartPoint().Row) + 1,
		ActLine:      actLine,
		HasDelay:     hasDelay,
		IsAtomic:     isAtomic,
	}
}

// extractVariableFromCondition 从条件表达式中提取变量名
func (d *AtomicityViolationDetector) extractVariableFromCondition(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}

	content := string(node.Content(source))

	// 简化版本：查找二元表达式中的变量
	// 例如: balance >= amount，我们提取 balance
	if node.Type() == "binary_expression" {
		// 获取左操作数
		if node.ChildCount() > 0 {
			left := node.Child(0)
			if left != nil && left.Type() == "identifier" {
				name := string(left.Content(source))
				return name
			}
		}
	}

	// 对于其他类型，尝试直接提取标识符
	if node.Type() == "identifier" {
		return content
	}

	// 递归搜索子节点中的标识符
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && child.Type() == "identifier" {
			name := string(child.Content(source))
			// 过滤掉函数名和关键字
			if name != "compare_exchange_weak" && name != "compare_exchange_strong" {
				return name
			}
		}
	}

	return ""
}

// findVariableUsageInBlock 在代码块中查找变量使用
func (d *AtomicityViolationDetector) findVariableUsageInBlock(block *sitter.Node, varName string, source []byte) (*sitter.Node, int, bool) {
	hasDelay := false

	// 遍历块中的所有语句
	for i := 0; i < int(block.ChildCount()); i++ {
		child := block.Child(i)
		if child == nil {
			continue
		}

		// 检查是否有 sleep 调用（明显的竞态窗口）
		if strings.Contains(string(child.Content(source)), "sleep") ||
			strings.Contains(string(child.Content(source)), "wait") {
			hasDelay = true
		}

		// 检查是否是对目标变量的赋值或操作
		if d.isVariableUsage(child, varName, source) {
			return child, int(child.StartPoint().Row) + 1, hasDelay
		}

		// 递归查找
		if result, line, delay := d.findVariableUsageInBlock(child, varName, source); result != nil {
			hasDelay = hasDelay || delay
			return result, line, hasDelay
		}
	}

	return nil, 0, hasDelay
}

// isVariableUsage 检查节点是否是对变量的使用（赋值、修改等）
func (d *AtomicityViolationDetector) isVariableUsage(node *sitter.Node, varName string, source []byte) bool {
	content := string(node.Content(source))

	// 检查是否包含变量名和赋值/操作符
	if strings.Contains(content, varName) {
		// 检查是否有赋值或自增/自减操作
		if strings.Contains(content, "=") && !strings.Contains(content, "==") {
			return true
		}
		if strings.Contains(content, "+=") || strings.Contains(content, "-=") ||
			strings.Contains(content, "*=") || strings.Contains(content, "/=") {
			return true
		}
		if strings.Contains(content, "++") || strings.Contains(content, "--") {
			return true
		}
	}

	return false
}

// detectAtomicityViolations 检测原子性违规
func (d *AtomicityViolationDetector) detectAtomicityViolations(ctx *core.AnalysisContext, source []byte) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	for _, pattern := range d.checkPatterns {
		// 只报告涉及 atomic 变量的模式，或者有明显延迟的模式
		if !pattern.IsAtomic && !pattern.HasDelay {
			continue
		}

		// 检查是否使用了 compare_exchange
		if d.usesCompareExchange(pattern.ActNode, source) {
			continue
		}

		// 生成漏洞报告
		message := d.formatViolationMessage(pattern)

		severity := "medium"
		if pattern.IsAtomic && pattern.HasDelay {
			severity = "high"
		}

		vulns = append(vulns, core.DetectorVulnerability{
			Type:       "CWE-360: Atomicity Violation",
			Message:    message,
			Severity:   severity,
			Confidence: "medium",
			Line:       pattern.CheckLine,
			Column:     0,
		})
	}

	return vulns
}

// usesCompareExchange 检查是否使用了 CAS 操作
func (d *AtomicityViolationDetector) usesCompareExchange(node *sitter.Node, source []byte) bool {
	content := string(node.Content(source))
	return strings.Contains(content, "compare_exchange")
}

// formatViolationMessage 格式化违规消息
func (d *AtomicityViolationDetector) formatViolationMessage(pattern *CheckActPattern) string {
	var msg string

	if pattern.IsAtomic {
		msg = fmt.Sprintf(
			"Atomicity violation detected for atomic variable '%s' at line %d. "+
				"The check and subsequent operation on the atomic variable are not atomic. "+
				"Even though '%s' is declared as atomic, separate load and store operations create a race condition. "+
				"Use compare_exchange_weak() or compare_exchange_strong() to ensure atomic check-and-act semantics.",
			pattern.VariableName, pattern.CheckLine, pattern.VariableName)
	} else {
		msg = fmt.Sprintf(
			"Potential atomicity violation for variable '%s' at line %d. "+
				"The check at line %d and use at line %d are not atomic, creating a time-of-check-to-time-of-use (TOCTOU) race window.",
			pattern.VariableName, pattern.CheckLine, pattern.CheckLine, pattern.ActLine)
	}

	if pattern.HasDelay {
		msg += " There is an explicit delay (sleep/wait) between check and act, increasing the race window."
	}

	return msg
}
