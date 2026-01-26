package detectors

import (
	"fmt"
	"strings"
	"sync"

	"gosast/internal/core"

	sitter "github.com/smacker/go-tree-sitter"
)

// PathTraversalDetector 路径遍历检测器 (CWE-22)
// 检测文件操作中的路径遍历漏洞
type PathTraversalDetector struct {
	*core.BaseDetector
	z3Solver core.Z3Solver
	mu       sync.RWMutex
}

// PathOpInfo 路径操作函数信息
type PathOpInfo struct {
	PathArg  int    // 路径参数索引
	Category string // 函数类别
}

// 危险的文件操作函数列表
var pathOperationFuncs = map[string]PathOpInfo{
	// 文件打开
	"fopen":   {PathArg: 0, Category: "file_open"},
	"open":    {PathArg: 0, Category: "file_open"},
	"fopen64": {PathArg: 0, Category: "file_open"},
	"open64":  {PathArg: 0, Category: "file_open"},
	"freopen": {PathArg: 0, Category: "file_open"},

	// 文件信息
	"stat":    {PathArg: 0, Category: "file_info"},
	"lstat":   {PathArg: 0, Category: "file_info"},
	"fstatat": {PathArg: 1, Category: "file_info"},
	"access":  {PathArg: 0, Category: "file_access"},

	// 文件删除
	"unlink":   {PathArg: 0, Category: "file_delete"},
	"unlinkat": {PathArg: 1, Category: "file_delete"},
	"remove":   {PathArg: 0, Category: "file_delete"},

	// 文件重命名
	"rename":   {PathArg: 0, Category: "file_move"},
	"renameat": {PathArg: 1, Category: "file_move"},

	// 目录操作
	"mkdir":    {PathArg: 0, Category: "dir_create"},
	"mkdirat":  {PathArg: 1, Category: "dir_create"},
	"rmdir":    {PathArg: 0, Category: "dir_delete"},
	"chdir":    {PathArg: 0, Category: "dir_change"},
	"fchdirat": {PathArg: 1, Category: "dir_change"},

	// 目录遍历
	"opendir":   {PathArg: 0, Category: "dir_open"},
	"scandir":   {PathArg: 0, Category: "dir_open"},
	"readdir":   {PathArg: 0, Category: "dir_read"},
	"readdir_r": {PathArg: 0, Category: "dir_read"},

	// 路径解析
	"realpath":               {PathArg: 0, Category: "path_resolve"},
	"canonicalize_file_name": {PathArg: 0, Category: "path_resolve"},

	// 其他文件操作
	"chmod":   {PathArg: 0, Category: "file_mode"},
	"chown":   {PathArg: 0, Category: "file_owner"},
	"lchown":  {PathArg: 0, Category: "file_owner"},
	"statvfs": {PathArg: 0, Category: "fs_info"},
}

// 敏感路径列表
var sensitivePaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/hosts",
	"/root/",
	"/home/",
	"/var/log/",
	"/proc/",
	"/sys/",
	"/etc/ssh/",
	"/etc/ssl/",
	"/etc/apache2/",
	"/etc/nginx/",
	".ssh/",
	".aws/",
	".env",
}

// NewPathTraversalDetector 创建路径遍历检测器
func NewPathTraversalDetector() *PathTraversalDetector {
	solver, _ := core.CreateZ3Solver()

	return &PathTraversalDetector{
		BaseDetector: core.NewBaseDetector(
			"Path Traversal Detector",
			"Detects path traversal vulnerabilities (CWE-22) using static pattern matching and taint analysis",
		),
		z3Solver: solver,
	}
}

// Name 返回检测器名称
func (d *PathTraversalDetector) Name() string {
	return "Path Traversal Detector"
}

// Description 返回检测器描述
func (d *PathTraversalDetector) Description() string {
	return d.BaseDetector.Description()
}

// Run 执行检测
func (d *PathTraversalDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// *** 改进 ***: 初始化污点分析引擎并执行跨函数污点传播
	ctx.InitTaintEngine()
	if err := ctx.RunCrossFunctionTaintPropagation(); err != nil {
		// 跨函数污点传播失败不是致命错误，继续执行
		fmt.Printf("[Warning] Cross-function taint propagation failed: %v\n", err)
	}

	// 1. 静态模式检测 - 检测硬编码的 "../" 模式
	staticVulns := d.detectStaticPatterns(ctx)
	vulns = append(vulns, staticVulns...)

	// 2. 污点分析检测 - 检测来自用户输入的路径参数
	taintedVulns := d.detectTaintedPaths(ctx)
	vulns = append(vulns, taintedVulns...)

	// 3. 绝对路径检测 - 检测访问敏感目录的绝对路径
	absoluteVulns := d.detectAbsolutePaths(ctx)
	vulns = append(vulns, absoluteVulns...)

	return vulns, nil
}

// detectStaticPatterns 检测静态路径遍历模式
// 查找代码中硬编码的 "../" 模式
func (d *PathTraversalDetector) detectStaticPatterns(ctx *core.AnalysisContext) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 查找所有字符串字面量
	query := `(string_literal) @str`
	matches, err := ctx.Query(query)
	if err != nil {
		return vulns
	}

	for _, match := range matches {
		text := ctx.GetSourceText(match.Node)

		// 检查是否包含路径遍历模式
		if d.containsTraversalPattern(text) {
			// 查找此字符串在哪个函数调用中使用
			if callSite := d.findCallSiteUsing(ctx, match.Node); callSite != nil {
				funcName := d.extractFunctionName(ctx, callSite)

				// 只报告在危险函数中使用的模式
				if _, isDangerous := pathOperationFuncs[funcName]; isDangerous {
					vuln := core.DetectorVulnerability{
						Type:       "CWE-22",
						Message:    fmt.Sprintf("Static path traversal pattern detected: %s used in %s()", text, funcName),
						Line:       int(callSite.StartPoint().Row) + 1,
						Column:     int(callSite.StartPoint().Column) + 1,
						Severity:   "high",
						Confidence: "high",
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}

// detectTaintedPaths 使用污点分析检测路径遍历
// 追踪来自用户输入的路径参数
func (d *PathTraversalDetector) detectTaintedPaths(ctx *core.AnalysisContext) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 查找所有危险函数调用
	query := `(call_expression) @call`
	matches, err := ctx.Query(query)
	if err != nil {
		return vulns
	}

	for _, match := range matches {
		funcName := d.extractFunctionName(ctx, match.Node)

		if info, isDangerous := pathOperationFuncs[funcName]; isDangerous {
			args := d.extractArguments(ctx, match.Node)

			if info.PathArg < len(args) {
				pathArg := args[info.PathArg]

				// *** 改进 ***: 使用函数作用域的污点检查，而不是全局污点检查
				isTainted := false
				if ctx.Taint != nil {
					engine := ctx.Taint.(*core.MemoryTaintEngine)
					if core.SafeType(pathArg) == "identifier" {
						// 获取当前函数名
						currentFuncName := ctx.GetContainingFunctionName(match.Node)
						if currentFuncName != "" {
							isTainted = engine.IsIdentifierTaintedInFunction(pathArg, currentFuncName)
						}
					}

					// 对于非 identifier 类型或函数名获取失败，回退到全局检查
					if !isTainted {
						isTainted = ctx.IsTainted(pathArg)
					}
				}

				// 检查参数是否被污染
				if isTainted {
					// 获取污点源
					source := d.getTaintSource(ctx, pathArg)

					severity := "high"
					confidence := "medium"

					// 如果是字符串拼接，置信度更高
					if d.isStringConcatenation(ctx, pathArg) {
						confidence = "high"
						severity = "critical"
					}

					// 检查是否是直接的用户输入函数调用
					if d.isDirectUserInput(ctx, pathArg) {
						confidence = "high"
						severity = "critical"
					}

					vuln := core.DetectorVulnerability{
						Type:       "CWE-22",
						Message:    fmt.Sprintf("Potential path traversal: tainted path argument to %s() from %s", funcName, source),
						Line:       int(match.Node.StartPoint().Row) + 1,
						Column:     int(match.Node.StartPoint().Column) + 1,
						Severity:   severity,
						Confidence: confidence,
						Source:     source,
					}
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}

// detectAbsolutePaths 检测访问敏感目录的绝对路径
func (d *PathTraversalDetector) detectAbsolutePaths(ctx *core.AnalysisContext) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 查找所有函数调用中的字符串字面量参数
	query := `
		(call_expression
			function: (identifier) @func
			arguments: (argument_list
				(string_literal) @path
			)
		) @call
	`

	matches, err := ctx.Query(query)
	if err != nil {
		return vulns
	}

	for _, match := range matches {
		funcNode, hasFunc := match.Captures["func"]
		pathNode, hasPath := match.Captures["path"]

		if !hasFunc || !hasPath {
			continue
		}

		funcName := ctx.GetSourceText(funcNode)
		path := ctx.GetSourceText(pathNode)

		// 检查是否是危险函数
		if _, isDangerous := pathOperationFuncs[funcName]; !isDangerous {
			continue
		}

		// 检查是否是绝对路径
		absolutePath := d.extractAbsolutePath(path)
		if absolutePath == "" {
			continue
		}

		// 检查路径是否指向敏感目录
		if d.isSensitivePath(absolutePath) {
			vuln := core.DetectorVulnerability{
				Type:       "CWE-22",
				Message:    fmt.Sprintf("Absolute path to sensitive directory: %s in %s()", absolutePath, funcName),
				Line:       int(match.Node.StartPoint().Row) + 1,
				Column:     int(match.Node.StartPoint().Column) + 1,
				Severity:   "medium",
				Confidence: "low",
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// containsTraversalPattern 检查字符串是否包含路径遍历模式
func (d *PathTraversalDetector) containsTraversalPattern(s string) bool {
	patterns := []string{
		`"../"`,
		`"..\\"`,      // Windows
		`"%2e%2e"`,    // URL 编码的 ..
		`"%2e%2e%2f"`, // URL 编码的 ./
		`"%2e%2e%5c"`, // URL 编码的 ..\
		`"..%255c"`,   // Windows IIS 编码
		`"0x2e0x2e"`,  // 十六进制编码
	}

	lowerS := strings.ToLower(s)
	for _, pattern := range patterns {
		if strings.Contains(lowerS, strings.ToLower(pattern)) {
			return true
		}
	}

	// 检查连续的 ../ 模式（如 "../../"）
	if strings.Contains(s, "../") || strings.Contains(s, "..\\") {
		return true
	}

	return false
}

// isSensitivePath 检查路径是否指向敏感目录
func (d *PathTraversalDetector) isSensitivePath(path string) bool {
	// 移除引号
	path = strings.Trim(path, `"`)
	path = strings.Trim(path, `'`)

	for _, sensitive := range sensitivePaths {
		if strings.Contains(path, sensitive) {
			return true
		}
	}

	// 检查常见的系统配置文件
	systemFiles := []string{
		"passwd", "shadow", "sudoers", "hosts",
		"ssh_config", "sshd_config",
		"authorized_keys", "id_rsa",
	}

	for _, file := range systemFiles {
		if strings.Contains(path, file) {
			return true
		}
	}

	return false
}

// extractAbsolutePath 从字符串字面量中提取绝对路径
func (d *PathTraversalDetector) extractAbsolutePath(s string) string {
	// 移除引号
	s = strings.Trim(s, `"`)
	s = strings.Trim(s, `'`)

	// 检查是否是绝对路径
	if strings.HasPrefix(s, "/") || strings.Contains(s, ":\\") {
		return s
	}

	return ""
}

// isStringConcatenation 检查节点是否是字符串拼接的结果
func (d *PathTraversalDetector) isStringConcatenation(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 检查是否是 strcat, strcpy, sprintf 的调用
	if node.Type() == "call_expression" {
		funcName := d.extractFunctionName(ctx, node)
		return funcName == "strcat" ||
			funcName == "strcpy" ||
			funcName == "sprintf" ||
			funcName == "snprintf"
	}

	// 检查父节点是否是拼接表达式
	parent := node.Parent()
	if parent != nil {
		if parent.Type() == "binary_expression" {
			// 检查操作符是否是 +
			opText := ctx.GetSourceText(parent)
			if strings.Contains(opText, "+") {
				return true
			}
		}
	}

	return false
}

// isDirectUserInput 检查节点是否直接来自用户输入函数
func (d *PathTraversalDetector) isDirectUserInput(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil || node.Type() != "call_expression" {
		return false
	}

	funcName := d.extractFunctionName(ctx, node)

	userInputFuncs := map[string]bool{
		"gets":     true,
		"scanf":    true,
		"fscanf":   true,
		"sscanf":   true,
		"fgets":    true,
		"read":     true,
		"recv":     true,
		"recvfrom": true,
		"getline":  true,
	}

	return userInputFuncs[funcName]
}

// extractFunctionName 从函数调用节点中提取函数名
func (d *PathTraversalDetector) extractFunctionName(ctx *core.AnalysisContext, callNode *sitter.Node) string {
	if callNode == nil {
		return ""
	}

	funcNode := callNode.ChildByFieldName("function")
	if funcNode != nil && funcNode.Type() == "identifier" {
		return ctx.GetSourceText(funcNode)
	}

	// 处理 pointer_expression 的情况（如结构体函数指针）
	if funcNode != nil && funcNode.Type() == "pointer_expression" {
		// 尝试获取最后一个标识符
		for i := int(funcNode.ChildCount()) - 1; i >= 0; i-- {
			child := funcNode.Child(i)
			if child != nil && child.Type() == "identifier" {
				return ctx.GetSourceText(child)
			}
		}
	}

	return ""
}

// extractArguments 从函数调用节点中提取参数列表
func (d *PathTraversalDetector) extractArguments(ctx *core.AnalysisContext, callNode *sitter.Node) []*sitter.Node {
	var args []*sitter.Node

	if callNode == nil {
		return args
	}

	argList := callNode.ChildByFieldName("arguments")
	if argList == nil {
		return args
	}

	for i := 0; i < int(argList.ChildCount()); i++ {
		arg := argList.Child(i)
		if arg != nil && arg.Type() != "(" && arg.Type() != ")" && arg.Type() != "," {
			args = append(args, arg)
		}
	}

	return args
}

// getTaintSource 获取节点的污点源
func (d *PathTraversalDetector) getTaintSource(ctx *core.AnalysisContext, node *sitter.Node) string {
	if ctx == nil || ctx.Taint == nil {
		return "unknown"
	}

	path := ctx.GetTaintPath(node)
	if len(path) > 0 && path[0].From != nil {
		return fmt.Sprintf("line %d", int(path[0].From.StartPoint().Row)+1)
	}

	// 尝试从节点本身推断
	if node.Type() == "identifier" {
		varName := ctx.GetSourceText(node)
		if varName != "" {
			return fmt.Sprintf("variable '%s'", varName)
		}
	}

	if node.Type() == "call_expression" {
		funcName := d.extractFunctionName(ctx, node)
		if funcName != "" {
			return fmt.Sprintf("return value of %s()", funcName)
		}
	}

	return "unknown"
}

// findCallSiteUsing 查找使用指定字符串的函数调用
func (d *PathTraversalDetector) findCallSiteUsing(ctx *core.AnalysisContext, strNode *sitter.Node) *sitter.Node {
	if strNode == nil {
		return nil
	}

	// 向上遍历 AST 查找包含此字符串的函数调用
	parent := strNode.Parent()
	maxDepth := 10
	depth := 0

	for parent != nil && depth < maxDepth {
		if parent.Type() == "call_expression" {
			return parent
		}
		parent = parent.Parent()
		depth++
	}

	return nil
}
