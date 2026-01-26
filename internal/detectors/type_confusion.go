package detectors

import (
	"fmt"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// TypeConfusionDetector 类型混淆检测器 (CWE-843)
// 检测使用不兼容类型访问资源的情况
// 主要场景：
// 1. static_cast 跨继承层次转换（没有运行时检查）
// 2. reinterpret_cast 强制类型转换
// 3. C 风格强制类型转换
// 4. void* 指针转换为不兼容类型
// 5. Union 成员访问不匹配
type TypeConfusionDetector struct {
	*core.BaseDetector
	// 类型信息收集
	classHierarchies  map[string]*ClassInfo // 类名 -> 类信息
	castExpressions   []*CastExpression     // 所有类型转换表达式
	unionDeclarations map[string]bool       // union 类型声明
	voidPtrCasts      []*CastExpression     // void* 转换
	mutex             sync.RWMutex
}

// ClassInfo 类继承信息
type ClassInfo struct {
	Name        string
	BaseClasses []string
	HasVirtual  bool
	LineNumber  int
}

// CastExpression 类型转换表达式
type CastExpression struct {
	CastNode   *sitter.Node
	CastType   string // "static_cast", "reinterpret_cast", "c_style_cast", "void_ptr_cast"
	SourceExpr string
	TargetType string
	LineNumber int
	IsDowncast bool // 是否是向下转换（基类 -> 派生类）
}

// NewTypeConfusionDetector 创建类型混淆检测器
func NewTypeConfusionDetector() *TypeConfusionDetector {
	return &TypeConfusionDetector{
		BaseDetector: core.NewBaseDetector(
			"Type Confusion Detector",
			"Detects access of resources using incompatible types (CWE-843)",
		),
		classHierarchies:  make(map[string]*ClassInfo),
		castExpressions:   make([]*CastExpression, 0),
		unionDeclarations: make(map[string]bool),
		voidPtrCasts:      make([]*CastExpression, 0),
	}
}

// Name 返回检测器名称
func (d *TypeConfusionDetector) Name() string {
	return "Type Confusion Detector"
}

// Run 运行检测器
func (d *TypeConfusionDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// 清空之前的数据
	d.classHierarchies = make(map[string]*ClassInfo)
	d.castExpressions = make([]*CastExpression, 0)
	d.unionDeclarations = make(map[string]bool)
	d.voidPtrCasts = make([]*CastExpression, 0)

	root := ctx.Unit.Root
	source := ctx.Unit.Source

	// 第1步：收集类继承层次结构
	d.collectClassHierarchies(ctx, root, source)

	// 第2步：收集所有类型转换表达式
	d.collectCastExpressions(ctx, root, source)

	// 第3步：收集 union 声明
	d.collectUnionDeclarations(ctx, root, source)

	// 第4步：检测类型混淆漏洞
	vulns := d.detectTypeConfusion(ctx, source)

	return vulns, nil
}

// collectClassHierarchies 收集类继承层次结构
func (d *TypeConfusionDetector) collectClassHierarchies(ctx *core.AnalysisContext, root *sitter.Node, source []byte) {
	visited := make(map[*sitter.Node]bool)

	var collectFunc func(*sitter.Node)
	collectFunc = func(node *sitter.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true

		// 检查是否是类定义
		if node.Type() == "class_specifier" {
			classInfo := d.parseClassDefinition(node, source)
			if classInfo != nil {
				d.classHierarchies[classInfo.Name] = classInfo
			}
		}

		// 递归处理子节点
		for i := 0; i < int(node.ChildCount()); i++ {
			collectFunc(node.Child(i))
		}
	}

	collectFunc(root)
}

// parseClassDefinition 解析类定义
func (d *TypeConfusionDetector) parseClassDefinition(node *sitter.Node, source []byte) *ClassInfo {
	var className string
	var baseClasses []string
	hasVirtual := false

	// 遍历类定义的子节点
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		// 查找类名（type_identifier）
		if child.Type() == "type_identifier" {
			className = string(child.Content(source))
		}

		// 查找基类列表（base_class_clause）
		if child.Type() == "base_class_clause" {
			baseClasses = d.parseBaseClasses(child, source)
		}

		// 检查是否有虚函数
		if d.hasVirtualFunction(child, source) {
			hasVirtual = true
		}
	}

	if className == "" {
		return nil
	}

	return &ClassInfo{
		Name:        className,
		BaseClasses: baseClasses,
		HasVirtual:  hasVirtual,
		LineNumber:  int(node.StartPoint().Row) + 1,
	}
}

// parseBaseClasses 解析基类列表
func (d *TypeConfusionDetector) parseBaseClasses(node *sitter.Node, source []byte) []string {
	var baseClasses []string

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		if child.Type() == "type_identifier" {
			baseClasses = append(baseClasses, string(child.Content(source)))
		}
	}

	return baseClasses
}

// hasVirtualFunction 检查是否有虚函数
func (d *TypeConfusionDetector) hasVirtualFunction(node *sitter.Node, source []byte) bool {
	if node == nil {
		return false
	}
	content := string(node.Content(source))
	return strings.Contains(content, "virtual")
}

// collectCastExpressions 收集类型转换表达式
func (d *TypeConfusionDetector) collectCastExpressions(ctx *core.AnalysisContext, root *sitter.Node, source []byte) {
	visited := make(map[*sitter.Node]bool)

	var collectFunc func(*sitter.Node)
	collectFunc = func(node *sitter.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true

		// 检查节点内容是否包含强制类型转换
		content := string(node.Content(source))

		// 检查 C++ 风格的强制类型转换（包括 static_cast, reinterpret_cast 等）
		// 这些可能被解析为不同的节点类型
		if strings.Contains(content, "static_cast") ||
			strings.Contains(content, "reinterpret_cast") ||
			strings.Contains(content, "const_cast") ||
			strings.Contains(content, "dynamic_cast") ||
			(node.Type() == "cast_expression") {
			// 只处理 call_expression 类型，避免重复
			if node.Type() == "call_expression" || node.Type() == "cast_expression" {
				castInfo := d.parseCastExpression(node, source)
				if castInfo != nil {
					d.castExpressions = append(d.castExpressions, castInfo)
					// 如果是 void* 转换，额外记录
					if castInfo.CastType == "void_ptr_cast" {
						d.voidPtrCasts = append(d.voidPtrCasts, castInfo)
					}
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

// parseCastExpression 解析类型转换表达式
func (d *TypeConfusionDetector) parseCastExpression(node *sitter.Node, source []byte) *CastExpression {
	content := string(node.Content(source))
	var castType string
	var targetType string

	// 首先检查节点类型，Tree-sitter 将 C++ cast 解析为 call_expression
	if node.Type() == "call_expression" {
		// 查找函数名（cast 类型）
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && child.Type() == "template_function" {
				funcContent := string(child.Content(source))
				if strings.HasPrefix(funcContent, "static_cast") {
					castType = "static_cast"
				} else if strings.HasPrefix(funcContent, "reinterpret_cast") {
					castType = "reinterpret_cast"
				} else if strings.HasPrefix(funcContent, "const_cast") {
					castType = "const_cast"
				} else if strings.HasPrefix(funcContent, "dynamic_cast") {
					castType = "dynamic_cast"
				}
				// 提取模板参数中的目标类型
				targetType = d.extractTypeFromTemplate(funcContent)
				break
			}
		}
	} else {
		// 检查转换类型（对于其他节点类型）
		if strings.Contains(content, "static_cast") {
			castType = "static_cast"
		} else if strings.Contains(content, "reinterpret_cast") {
			castType = "reinterpret_cast"
		} else if strings.Contains(content, "const_cast") {
			castType = "const_cast"
		} else if strings.Contains(content, "dynamic_cast") {
			castType = "dynamic_cast"
		} else {
			// C 风格强制类型转换: (Type)expr
			castType = "c_style_cast"
		}

		// 提取目标类型
		targetType = d.extractTargetType(node, source)
	}

	if targetType == "" {
		return nil
	}

	return &CastExpression{
		CastNode:   node,
		CastType:   castType,
		SourceExpr: content,
		TargetType: targetType,
		LineNumber: int(node.StartPoint().Row) + 1,
	}
}

// extractTypeFromTemplate 从模板函数调用中提取类型
func (d *TypeConfusionDetector) extractTypeFromTemplate(templateContent string) string {
	// 例如: "static_cast<Greeter*>" 或 "dynamic_cast<Type*>"
	// 提取 < 和 > 之间的类型
	start := strings.Index(templateContent, "<")
	end := strings.Index(templateContent, ">")

	if start == -1 || end == -1 || end <= start {
		return ""
	}

	typeStr := templateContent[start+1 : end]
	// 去掉可能的指针符号
	typeStr = strings.TrimSuffix(typeStr, "*")
	typeStr = strings.TrimSpace(typeStr)

	return typeStr
}

// extractTargetType 提取目标类型
func (d *TypeConfusionDetector) extractTargetType(node *sitter.Node, source []byte) string {
	// 在 cast_expression 中查找类型标识符
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		// 对于 <type> 格式的 C++ cast
		if child.Type() == "type_identifier" || child.Type() == "template_type" {
			return string(child.Content(source))
		}

		// 对于 C 风格的 (Type)expr，查找括号内的类型
		if child.Type() == "(" {
			// 查找括号后的下一个节点，可能是类型
			if i+1 < int(node.ChildCount()) {
				nextChild := node.Child(i + 1)
				if nextChild != nil {
					content := string(nextChild.Content(source))
					// 简单的类型名
					if nextChild.Type() == "type_identifier" {
						return content
					}
					// 带指针的类型，如 "int*"
					if strings.HasSuffix(content, "*") {
						return strings.TrimSuffix(content, "*")
					}
				}
			}
		}
	}

	return ""
}

// collectUnionDeclarations 收集 union 声明
func (d *TypeConfusionDetector) collectUnionDeclarations(ctx *core.AnalysisContext, root *sitter.Node, source []byte) {
	visited := make(map[*sitter.Node]bool)

	var collectFunc func(*sitter.Node)
	collectFunc = func(node *sitter.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true

		// 检查是否是 union 定义
		if node.Type() == "union_specifier" {
			// 提取 union 名称
			for i := 0; i < int(node.ChildCount()); i++ {
				child := node.Child(i)
				if child != nil && child.Type() == "type_identifier" {
					unionName := string(child.Content(source))
					d.unionDeclarations[unionName] = true
					break
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

// detectTypeConfusion 检测类型混淆漏洞
func (d *TypeConfusionDetector) detectTypeConfusion(ctx *core.AnalysisContext, source []byte) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	for _, cast := range d.castExpressions {
		// 跳过 dynamic_cast（有运行时检查）
		if cast.CastType == "dynamic_cast" {
			continue
		}

		// 【优化】检查是否在 JNI 上下文中，如果是则跳过或降级
		if d.isJNIContext(ctx, cast, source) {
			// JNI 上下文中的 reinterpret_cast 是标准做法，跳过
			continue
		}

		// 检测不安全的 static_cast
		if cast.CastType == "static_cast" {
			if vuln := d.checkUnsafeStaticCast(cast, source); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}

		// 检测 reinterpret_cast
		if cast.CastType == "reinterpret_cast" {
			if vuln := d.checkReinterpretCast(cast, source); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}

		// 检测 void* 转换
		if cast.CastType == "c_style_cast" && strings.Contains(cast.SourceExpr, "void") {
			if vuln := d.checkVoidPtrCast(cast, source); vuln != nil {
				vulns = append(vulns, *vuln)
			}
		}
	}

	return vulns
}

// isJNIContext 检查类型转换是否在 JNI 上下文中
// JNI (Java Native Interface) 代码中使用 reinterpret_cast 是标准做法
// 用于将 Java 的 jlong/jobject 句柄转换为 C++ 对象指针
func (d *TypeConfusionDetector) isJNIContext(ctx *core.AnalysisContext, cast *CastExpression, source []byte) bool {
	// 检查1：目标类型是否是 JNI 句柄相关的类型
	jniTypes := []string{
		"jlong", "jobject", "jclass", "jstring", "jarray",
		"jbyteArray", "jintArray", "jlongArray", "jobjectArray",
		"jboolean", "jbyte", "jchar", "jshort", "jint", "jlong", "jfloat", "jdouble",
		"JNIEnv", "jfieldID", "jmethodID",
	}

	// 检查源表达式或目标类型是否包含 JNI 类型
	sourceLower := strings.ToLower(cast.SourceExpr)
	targetLower := strings.ToLower(cast.TargetType)

	for _, jniType := range jniTypes {
		if strings.Contains(sourceLower, strings.ToLower(jniType)) ||
			strings.Contains(targetLower, strings.ToLower(jniType)) {
			return true
		}
	}

	// 检查2：查找包含此转换的函数是否是 JNI 函数
	// JNI 函数命名规则: Java_<package>_<class>_<method>
	functionNode := d.findContainingFunction(ctx, cast.CastNode)
	if functionNode != nil {
		funcName := d.extractFunctionName(ctx, functionNode, source)
		if strings.HasPrefix(funcName, "Java_") {
			return true
		}
	}

	// 检查3：检查文件是否包含 jni.h 头文件
	if d.includesJNIHeader(ctx) {
		// 如果文件包含 jni.h，且转换发生在可能 JNI 相关的函数中
		// 检查是否有常见的 JNI 模式
		if d.hasJNIPatterns(cast, source) {
			return true
		}
	}

	return false
}

// findContainingFunction 查找包含给定节点的函数
func (d *TypeConfusionDetector) findContainingFunction(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
	current := node
	for current != nil {
		if current.Type() == "function_definition" || current.Type() == "function_declarator" {
			return current
		}
		current = current.Parent()
	}
	return nil
}

// extractFunctionName 提取函数名
func (d *TypeConfusionDetector) extractFunctionName(ctx *core.AnalysisContext, funcNode *sitter.Node, source []byte) string {
	// 查找 function_declarator 节点
	declarator := core.SafeChildByFieldName(funcNode, "declarator")
	if declarator == nil {
		declarator = funcNode
	}

	// 查找 identifier 子节点
	for i := 0; i < int(core.SafeChildCount(declarator)); i++ {
		child := core.SafeChild(declarator, i)
		if child.Type() == "identifier" {
			return ctx.GetSourceText(child)
		}
	}

	return ""
}

// includesJNIHeader 检查文件是否包含 JNI 头文件
func (d *TypeConfusionDetector) includesJNIHeader(ctx *core.AnalysisContext) bool {
	// 查找所有 #include 指令
	includes, _ := ctx.QueryNodes(`(preproc_include (preproc_path) @path)`)

	for _, include := range includes {
		path := ctx.GetSourceText(include)
		if strings.Contains(path, "jni.h") || strings.Contains(path, "jni") {
			return true
		}
	}

	return false
}

// hasJNIPatterns 检查是否有 JNI 相关的代码模式
func (d *TypeConfusionDetector) hasJNIPatterns(cast *CastExpression, source []byte) bool {
	// 检查目标类型是否可能是 C++ 对象指针（JNI 中常见的转换目标）
	if strings.Contains(cast.TargetType, "NAMESPACE") ||
		strings.Contains(cast.TargetType, "::") {
		return true
	}

	// 检查源表达式是否像句柄变量名（常见模式: handle, ptr, context 等）
	sourceLower := strings.ToLower(cast.SourceExpr)
	handleKeywords := []string{"handle", "ptr", "context", "_obj", "_ptr"}
	for _, keyword := range handleKeywords {
		if strings.Contains(sourceLower, keyword) {
			return true
		}
	}

	return false
}

// checkUnsafeStaticCast 检查不安全的 static_cast
func (d *TypeConfusionDetector) checkUnsafeStaticCast(cast *CastExpression, source []byte) *core.DetectorVulnerability {
	// 检查是否是跨继承层次的转换
	targetClass := cast.TargetType

	// 查找目标类是否在继承层次中
	targetInfo := d.classHierarchies[targetClass]
	if targetInfo == nil {
		// 不是已知类，可能是基本类型转换，不算类型混淆
		return nil
	}

	// 如果目标类有基类，检查这是否是向下转换
	if len(targetInfo.BaseClasses) > 0 {
		// 向下转换（基类 -> 派生类）在没有运行时检查的情况下是危险的
		message := fmt.Sprintf(
			"Unsafe static_cast from base class to derived class '%s' at line %d. "+
				"static_cast does not perform runtime type checking. "+
				"Use dynamic_cast instead for safe down-casting.",
			targetClass, cast.LineNumber)

		return &core.DetectorVulnerability{
			Type:       "CWE-843: Type Confusion",
			Message:    message,
			Severity:   "high",
			Confidence: "medium",
			Line:       cast.LineNumber,
			Column:     0,
		}
	}

	return nil
}

// checkReinterpretCast 检查 reinterpret_cast
func (d *TypeConfusionDetector) checkReinterpretCast(cast *CastExpression, source []byte) *core.DetectorVulnerability {
	// reinterpret_cast 总是危险的，因为它不进行任何类型检查
	message := fmt.Sprintf(
		"Dangerous reinterpret_cast to type '%s' at line %d. "+
			"reinterpret_cast completely bypasses type safety and can lead to type confusion. "+
			"Ensure the cast is semantically correct.",
		cast.TargetType, cast.LineNumber)

	return &core.DetectorVulnerability{
		Type:       "CWE-843: Type Confusion",
		Message:    message,
		Severity:   "high",
		Confidence: "medium",
		Line:       cast.LineNumber,
		Column:     0,
	}
}

// checkVoidPtrCast 检查 void* 转换
func (d *TypeConfusionDetector) checkVoidPtrCast(cast *CastExpression, source []byte) *core.DetectorVulnerability {
	// void* 转换为具体类型是危险的，因为没有类型信息
	message := fmt.Sprintf(
		"Unsafe cast from void* to type '%s' at line %d. "+
			"Casting from void* bypasses type safety and can lead to type confusion. "+
			"Ensure the original object type matches the target type.",
		cast.TargetType, cast.LineNumber)

	return &core.DetectorVulnerability{
		Type:       "CWE-843: Type Confusion",
		Message:    message,
		Severity:   "medium",
		Confidence: "medium",
		Line:       cast.LineNumber,
		Column:     0,
	}
}
