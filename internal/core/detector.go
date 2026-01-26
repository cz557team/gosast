package core

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
)

// DetectorVulnerability 表示检测器发现的漏洞
type DetectorVulnerability struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Confidence string `json:"confidence"`
	Severity   string `json:"severity"`
	Source     string `json:"source,omitempty"` // 污染源（可选）
}

// Detector 检测器接口
type Detector interface {
	// Name 返回检测器名称
	Name() string

	// Description 返回检测器描述
	Description() string

	// Run 执行检测
	Run(ctx *AnalysisContext) ([]DetectorVulnerability, error)
}

// BaseDetector 基础检测器，提供通用功能
type BaseDetector struct {
	name        string
	description string
}

// NewBaseDetector 创建基础检测器
func NewBaseDetector(name, description string) *BaseDetector {
	return &BaseDetector{
		name:        name,
		description: description,
	}
}

// Name 返回检测器名称
func (d *BaseDetector) Name() string {
	return d.name
}

// Description 返回检测器描述
func (d *BaseDetector) Description() string {
	return d.description
}

// CreateVulnerability 创建漏洞对象
func (d *BaseDetector) CreateVulnerability(vulnType, message string, node *sitter.Node, confidence, severity string) DetectorVulnerability {
	vuln := DetectorVulnerability{
		Type:       vulnType,
		Message:    message,
		Line:       int(node.StartPoint().Row) + 1, // 转换为1基索引
		Column:     int(node.StartPoint().Column) + 1,
		Confidence: confidence,
		Severity:   severity,
	}

	return vuln
}

// TaintedVulnerability 创建带污点源的漏洞
func (d *BaseDetector) TaintedVulnerability(vulnType, message string, node *sitter.Node, source string, confidence, severity string) DetectorVulnerability {
	vuln := d.CreateVulnerability(vulnType, message, node, confidence, severity)
	vuln.Source = source
	return vuln
}

// Helper functions for detectors

// IsInUnsafeFunction 检查节点是否在不安全的函数中
func IsInUnsafeFunction(ctx *AnalysisContext, node *sitter.Node, unsafeFuncs []string) bool {
	parent := node.Parent()

	for parent != nil {
		if parent.Type() == "function_definition" {
			// 查找函数名
			funcName := FindFunctionName(parent)
			if funcName != "" {
				for _, unsafe := range unsafeFuncs {
					if funcName == unsafe {
						return true
					}
				}
			}
		}
		parent = parent.Parent()
	}

	return false
}

// FindFunctionName 查找函数定义的名称
func FindFunctionName(funcNode *sitter.Node) string {
	if funcNode.Type() != "function_definition" {
		return ""
	}

	// 查找函数声明符
	declarator := funcNode.ChildByFieldName("declarator")
	if declarator == nil {
		return ""
	}

	// 递归查找标识符
	var findIdentifier func(*sitter.Node) *sitter.Node
	findIdentifier = func(node *sitter.Node) *sitter.Node {
		if node == nil {
			return nil
		}

		if node.Type() == "identifier" {
			return node
		}

		// 检查第一个子节点
		if node.ChildCount() > 0 {
			return findIdentifier(node.Child(0))
		}

		return nil
	}

	idNode := findIdentifier(declarator)
	if idNode == nil {
		return ""
	}

	// 这里需要从 AnalysisContext 获取源代码文本
	// 暂时返回占位符
	return "function"
}

// IsCallToFunction 检查节点是否是对指定函数的调用
func IsCallToFunction(ctx *AnalysisContext, node *sitter.Node, functionName string) bool {
	if node.Type() != "call_expression" {
		return false
	}

	funcNode := node.ChildByFieldName("function")
	if funcNode == nil || funcNode.Type() != "identifier" {
		return false
	}

	// 这里需要比较函数名
	// 暂时使用简单的比较
	return true // TODO: 实现实际的函数名比较
}

// GetVariableName 从节点中获取变量名
func GetVariableName(ctx *AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return ""
	}

	switch node.Type() {
	case "identifier":
		// TODO: 从 AnalysisContext 获取实际的标识符文本
		return "variable"
	case "pointer_expression":
		return GetVariableName(ctx, node.Child(0))
	case "subscript_expression":
		return GetVariableName(ctx, node.Child(0))
	default:
		return ""
	}
}

// GetCalleeName 从调用表达式中获取被调用函数名
func GetCalleeName(ctx *AnalysisContext, callNode *sitter.Node) string {
	if callNode.Type() != "call_expression" {
		return ""
	}

	funcNode := callNode.ChildByFieldName("function")
	if funcNode == nil {
		return ""
	}

	// 查找标识符
	var findIdentifier func(*sitter.Node) *sitter.Node
	findIdentifier = func(node *sitter.Node) *sitter.Node {
		if node == nil {
			return nil
		}

		if node.Type() == "identifier" {
			return node
		}

		if node.ChildCount() > 0 {
			return findIdentifier(node.Child(0))
		}

		return nil
	}

	idNode := findIdentifier(funcNode)
	if idNode == nil {
		return ""
	}

	// TODO: 从源码中获取实际标识符
	return "callee"
}

// ResolveCrossFileCall 解析跨文件调用
func ResolveCrossFileCall(ctx *AnalysisContext, callNode *sitter.Node) *Symbol {
	if ctx.CrossFileAnalyzer == nil || ctx.SymbolResolver == nil {
		return nil
	}

	calleeName := GetCalleeName(ctx, callNode)
	if calleeName == "" {
		return nil
	}

	return ctx.SymbolResolver.ResolveFunctionCall(calleeName, ctx.Unit.FilePath)
}

// FindCallSites 查找所有调用点
func FindCallSites(ctx *AnalysisContext) []*CallSite {
	// 这里应该实现从AST中查找所有函数调用
	// 目前返回空列表
	return []*CallSite{}
}

// IsCrossFileCall 检查是否为跨文件调用
func IsCrossFileCall(ctx *AnalysisContext, callNode *sitter.Node) bool {
	symbol := ResolveCrossFileCall(ctx, callNode)
	if symbol == nil {
		return false
	}

	return symbol.FilePath != ctx.Unit.FilePath
}

// GetCrossFileDependencies 获取跨文件依赖关系
func GetCrossFileDependencies(ctx *AnalysisContext) map[string][]string {
	if ctx.CrossFileAnalyzer == nil {
		return nil
	}

	return ctx.CrossFileAnalyzer.GetSymbolResolver().GetCrossFileDependencies(ctx.Unit.FilePath)
}

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Confidence levels
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// CWE IDs
const (
	CWE415 = "CWE-415" // Double Free
	CWE416 = "CWE-416" // Use After Free
	CWE120 = "CWE-120" // Buffer Overflow
	CWE190 = "CWE-190" // Integer Overflow
	CWE476 = "CWE-476" // Null Pointer Dereference
	CWE122 = "CWE-122" // Heap Overflow
	CWE78  = "CWE-78"  // OS Command Injection
	CWE89  = "CWE-89"  // SQL Injection
	CWE125 = "CWE-125" // Out-of-bounds Read
	CWE119 = "CWE-119" // Improper Restriction of Operations
	CWE20  = "CWE-20"  // Input Validation
	CWE22  = "CWE-22"  // Path Traversal
	CWE787 = "CWE-787" // Out-of-bounds Write
	CWE134 = "CWE-134" // Use of Externally-Controlled Format String
	CWE191 = "CWE-191" // Integer Underflow
	CWE195 = "CWE-195" // Signed to Unsigned Conversion Error
	CWE362 = "CWE-362" // Race Condition (Deadlock)
	CWE667 = "CWE-667" // Improper Locking
	CWE776 = "CWE-776" // Missing Release of Resource
)

// ErrorWrapper 包装检测器错误
type ErrorWrapper struct {
	DetectorName string
	Err          error
}

func (e *ErrorWrapper) Error() string {
	return fmt.Sprintf("detector %s: %v", e.DetectorName, e.Err)
}

// WrapError 包装检测器错误
func WrapError(detector Detector, err error) error {
	return &ErrorWrapper{
		DetectorName: detector.Name(),
		Err:          err,
	}
}