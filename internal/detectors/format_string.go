package detectors

import (
	"fmt"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// FormatStringDetector 格式化字符串漏洞检测器 (CWE-134)
// V2: 使用迭代遍历替代递归，避免栈溢出
// 阶段1改进：添加格式化输出长度计算
type FormatStringDetector struct {
	*core.BaseDetector
	// 【阶段1新增】长度分析相关
	bufferSizes map[string]int64 // 缓冲区大小映射
}

// NewFormatStringDetector 创建新的格式化字符串检测器
func NewFormatStringDetector() *FormatStringDetector {
	return &FormatStringDetector{
		BaseDetector: core.NewBaseDetector(
			"format_string",
			"Detects format string vulnerabilities (CWE-134) using improved taint analysis",
		),
		bufferSizes: make(map[string]int64), // 阶段1新增
	}
}

// Name 返回检测器名称
func (d *FormatStringDetector) Name() string {
	return "Format String Detector"
}

// Description 返回检测器描述
func (d *FormatStringDetector) Description() string {
	return "Detects potential format string vulnerabilities using improved taint analysis (V2: Iterative traversal)"
}

// Run 执行检测
func (d *FormatStringDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 【阶段1新增】收集缓冲区大小信息
	d.collectBufferSizes(ctx)

	// 使用 Tree-sitter 查询查找所有格式化字符串函数调用
	// 比递归遍历更高效且不会栈溢出
	query := `
		(call_expression
			function: (identifier) @func
			arguments: (argument_list) @args
		) @call
	`

	matches, err := ctx.Query(query)
	if err != nil {
		return nil, err
	}

	for _, match := range matches {
		funcNode := match.Captures["func"]
		argsNode := match.Captures["args"]

		if funcNode == nil || argsNode == nil {
			continue
		}

		funcName := strings.TrimSpace(ctx.GetSourceText(funcNode))

		// 检查是否为格式化字符串函数
		if !d.isFormatStringFunction(funcName) {
			continue
		}

		// 检查漏洞
		d.checkFormatStringCall(ctx, match.Node, funcName, argsNode, &vulns)
	}

	return vulns, nil
}

// checkFormatStringCall 检查格式化字符串函数调用
func (d *FormatStringDetector) checkFormatStringCall(ctx *core.AnalysisContext, callNode *sitter.Node, funcName string, args *sitter.Node, vulns *[]core.DetectorVulnerability) {
	line := int(callNode.StartPoint().Row) + 1

	// 检查第一个参数（格式字符串）是否被污染
	if d.isFormatStringTainted(ctx, args, funcName) {
		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE134,
			fmt.Sprintf("Format string vulnerability: user-controlled format string at line %d in function %s", line, funcName),
			callNode,
			core.ConfidenceMedium,
			core.SeverityHigh,
		)
		*vulns = append(*vulns, vuln)
	}

	// 检查是否使用了 %n 格式符（高危）
	if d.usesDangerousFormatSpecifier(ctx, args, funcName) {
		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE134,
			fmt.Sprintf("Dangerous format specifier %%n at line %d in function %s", line, funcName),
			callNode,
			core.ConfidenceHigh,
			core.SeverityCritical,
		)
		*vulns = append(*vulns, vuln)
	}
}

// isFormatStringTainted 检查格式字符串是否被污染
func (d *FormatStringDetector) isFormatStringTainted(ctx *core.AnalysisContext, args *sitter.Node, funcName string) bool {
	// 对于 sprintf/snprintf 等，格式字符串是第二个参数（第一个是目标缓冲区）
	// 对于 printf/fprintf 等，格式字符串是第一个参数
	formatArg := d.extractFormatStringArg(ctx, args, funcName)
	if formatArg == nil {
		return false
	}

	// 检查第一个参数是否为字符串字面量
	if formatArg.Type() == "string_literal" {
		return false // 字符串字面量是安全的
	}

	// 检查是否为条件表达式（三元运算符），两个分支都是字面量
	if formatArg.Type() == "conditional_expression" {
		if d.isConditionalExpressionSafe(ctx, formatArg) {
			return false
		}
		// 否则视为可能不安全
		return true
	}

	// 检查第一个参数是否为标识符（可能是变量）
	if formatArg.Type() == "identifier" {
		varName := strings.TrimSpace(ctx.GetSourceText(formatArg))
		// 简化检查：检查变量名是否可能来自用户输入
		return d.isVariablePossiblyTainted(varName)
	}

	// 检查第一个参数是否为更复杂的表达式
	if formatArg.Type() == "binary_expression" ||
		formatArg.Type() == "call_expression" {
		// 复杂表达式也可能包含用户输入
		return true
	}

	return false
}

// isConditionalExpressionSafe 检查条件表达式的两个分支是否都是字符串字面量
func (d *FormatStringDetector) isConditionalExpressionSafe(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 条件表达式的结构：condition ? true_value : false_value
	// 检查 true_value 和 false_value 是否都是字符串字面量

	// Tree-sitter 的 conditional_expression 有以下字段：
	// - condition: 条件
	// - consequence: true 分支
	// - alternative: false 分支

	consequence := core.SafeChildByFieldName(node, "consequence")
	alternative := core.SafeChildByFieldName(node, "alternative")

	// 检查两个分支是否都是字符串字面量
	bothLiterals := true
	if consequence != nil && consequence.Type() != "string_literal" {
		bothLiterals = false
	}
	if alternative != nil && alternative.Type() != "string_literal" {
		bothLiterals = false
	}

	return bothLiterals
}

// isVariablePossiblyTainted 检查变量是否可能被污染（简化版）
func (d *FormatStringDetector) isVariablePossiblyTainted(varName string) bool {
	// 检查变量名是否包含典型的用户输入相关关键词
	taintedKeywords := []string{
		"input", "user", "buf", "buffer", "data", "str", "string",
		"msg", "message", "arg", "param", "name", "file", "path",
	}

	varNameLower := strings.ToLower(varName)
	for _, keyword := range taintedKeywords {
		if strings.Contains(varNameLower, keyword) {
			return true
		}
	}

	return false
}

// extractFormatStringArg 提取格式字符串参数
// 对于 sprintf/snprintf，格式字符串是第二个参数（索引 1）
// 对于 snprintf，格式字符串是第三个参数（索引 2），需要跳过 dest 和 size
// 对于 printf/fprintf，格式字符串是第一个参数（索引 0）
func (d *FormatStringDetector) extractFormatStringArg(ctx *core.AnalysisContext, args *sitter.Node, funcName string) *sitter.Node {
	if args.Type() != "argument_list" {
		return nil
	}

	// 判断格式字符串参数的索引
	formatArgIndex := d.getFormatStringIndex(funcName)

	return d.extractArgumentAt(args, formatArgIndex)
}

// getFormatStringIndex 获取格式字符串参数的索引
func (d *FormatStringDetector) getFormatStringIndex(funcName string) int {
	// 默认是第一个参数（printf, vprintf, syslog）
	index := 0

	switch funcName {
	case "sprintf", "vsprintf":
		index = 1 // 跳过目标缓冲区
	case "snprintf", "vsnprintf":
		index = 2 // 跳过目标缓冲区和大小
	case "fprintf", "vfprintf":
		index = 1 // 跳过文件流
	}

	return index
}

// needsDestBuffer 判断函数是否需要目标缓冲区参数
func (d *FormatStringDetector) needsDestBuffer(funcName string) bool {
	needBufFuncs := []string{
		"sprintf", "snprintf", "vsprintf", "vsnprintf",
		"fprintf", "vfprintf",
	}

	for _, fname := range needBufFuncs {
		if funcName == fname {
			return true
		}
	}
	return false
}

// extractArgumentAt 提取指定索引的参数
func (d *FormatStringDetector) extractArgumentAt(args *sitter.Node, index int) *sitter.Node {
	if args.Type() != "argument_list" {
		return nil
	}

	currentIndex := 0
	for i := 0; i < int(core.SafeChildCount(args)); i++ {
		child := core.SafeChild(args, i)
		childType := core.SafeType(child)

		// 跳过标点符号
		if childType == "," || childType == "(" || childType == ")" {
			continue
		}

		if currentIndex == index {
			return child
		}

		currentIndex++
	}

	return nil
}

// extractFirstArgument 提取第一个实际参数
func (d *FormatStringDetector) extractFirstArgument(args *sitter.Node) *sitter.Node {
	if args.Type() == "argument_list" {
		// 查找第一个非标点符号的参数
		for i := 0; i < int(core.SafeChildCount(args)); i++ {
			child := core.SafeChild(args, i)
			childType := core.SafeType(child)

			// 跳过标点符号
			if childType == "," || childType == "(" || childType == ")" {
				continue
			}

			return child
		}
	}
	return nil
}

// usesDangerousFormatSpecifier 检查是否使用危险格式符
func (d *FormatStringDetector) usesDangerousFormatSpecifier(ctx *core.AnalysisContext, args *sitter.Node, funcName string) bool {
	if core.SafeChildCount(args) == 0 {
		return false
	}

	// 检查格式字符串参数是否包含 %n
	formatArg := d.extractFormatStringArg(ctx, args, funcName)
	if formatArg == nil {
		return false
	}

	// 如果是字符串字面量，直接检查
	if core.SafeType(formatArg) == "string_literal" {
		formatText := ctx.GetSourceText(formatArg)
		return strings.Contains(formatText, "%n")
	}

	// 如果是变量或表达式，保守估计为可能包含（实际实现中可更精确）
	return false
}

// isFormatStringFunction 检查是否为格式化字符串函数
func (d *FormatStringDetector) isFormatStringFunction(funcName string) bool {
	formatFunctions := []string{
		"printf", "fprintf", "sprintf", "snprintf", "vprintf",
		"vfprintf", "vsprintf", "vsnprintf", "dprintf", "syslog",
	}

	for _, fname := range formatFunctions {
		if funcName == fname {
			return true
		}
	}
	return false
}

// ==================== 阶段1改进：格式化输出长度计算 ====================

// collectBufferSizes 收集缓冲区大小信息
func (d *FormatStringDetector) collectBufferSizes(ctx *core.AnalysisContext) {
	// 查找所有数组声明
	query := `(array_declarator) @array`
	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	for _, match := range matches {
		arrayDecl := match.Node
		varName, size := d.parseArrayDeclarator(ctx, arrayDecl)
		if varName != "" && size > 0 {
			d.bufferSizes[varName] = size
		}
	}
}

// parseArrayDeclarator 解析数组声明器
func (d *FormatStringDetector) parseArrayDeclarator(ctx *core.AnalysisContext, arrayDecl *sitter.Node) (string, int64) {
	var varName string
	var size int64

	for i := 0; i < int(core.SafeChildCount(arrayDecl)); i++ {
		child := core.SafeChild(arrayDecl, i)
		if core.SafeType(child) == "identifier" {
			varName = ctx.GetSourceText(child)
		} else if core.SafeType(child) == "number_literal" {
			text := ctx.GetSourceText(child)
			if val, err := strconv.ParseInt(text, 0, 64); err == nil {
				size = val
			}
		}
	}

	return varName, size
}

// estimateFormatOutputLength 估算格式化输出的最大长度
// 返回：(最小长度, 最大长度)
func (d *FormatStringDetector) estimateFormatOutputLength(ctx *core.AnalysisContext, formatArg *sitter.Node, args *sitter.Node, funcName string) (int64, int64) {
	if formatArg == nil {
		return 0, -1 // unknown
	}

	// 获取格式字符串
	var formatStr string
	if core.SafeType(formatArg) == "string_literal" {
		// 去掉引号
		text := ctx.GetSourceText(formatArg)
		if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
			formatStr = text[1 : len(text)-1]
		} else {
			formatStr = text
		}
	} else {
		// 动态格式字符串，无法静态分析
		return 0, -1
	}

	// 解析格式字符串，估算输出长度
	minLen := int64(0)
	maxLen := int64(0)
	argIndex := 0

	i := 0
	for i < len(formatStr) {
		if formatStr[i] == '%' && i+1 < len(formatStr) {
			// 解析格式符
			spec, _, newI := d.parseFormatSpecifier(formatStr, i)
			i = newI

			// 获取对应的参数
			var argNode *sitter.Node
			if funcName == "sprintf" || funcName == "snprintf" {
				// sprintf的第一个参数是目标缓冲区，第二个是格式字符串
				// 所以格式参数从索引2开始
				argIndex += 1
				argNode = d.extractArgumentAtNew(args, argIndex+1) // +1 跳过目标缓冲区
			} else {
				argIndex += 1
				argNode = d.extractArgumentAtNew(args, argIndex)
			}

			// 根据格式符类型估算长度
			switch spec {
			case "%d", "%i", "%u", "%x", "%X", "%o":
				// 整数：最大11位（包括符号）
				minLen += 1
				maxLen += 11
			case "%ld", "%lld", "%li", "%lli", "%lu", "%llu":
				// 长整数：最大21位
				minLen += 1
				maxLen += 21
			case "%f", "%lf":
				// 浮点数：最大317位（虽然实际很少这么大）
				minLen += 1
				maxLen += 317
			case "%s":
				// 字符串：关键！需要检查参数
				if argNode != nil {
					sLen := d.estimateStringLength(ctx, argNode)
					if sLen >= 0 {
						minLen += sLen
						maxLen += sLen
					} else {
						// 动态字符串，无法确定
						maxLen = -1
					}
				} else {
					maxLen = -1
				}
			case "%c":
				// 单个字符
				minLen += 1
				maxLen += 1
			case "%p":
				// 指针：最大18位（0x + 16位十六进制）
				minLen += 3
				maxLen += 18
			case "%%":
				// %% 输出 %
				minLen += 1
				maxLen += 1
			default:
				// 未知格式符，保守估计
				minLen += 1
				maxLen += 50
			}
		} else {
			// 普通字符
			minLen++
			maxLen++
			i++
		}
	}

	// 加上null终止符
	minLen++
	if maxLen >= 0 {
		maxLen++
	}

	return minLen, maxLen
}

// parseFormatSpecifier 解析格式符
// 返回：(格式符, 长度修饰符, 下一个位置)
func (d *FormatStringDetector) parseFormatSpecifier(formatStr string, start int) (string, int64, int) {
	if start >= len(formatStr) || formatStr[start] != '%' {
		return "", 0, start
	}

	i := start + 1
	lengthMod := int64(0)

	// 跳过标志字符
	for i < len(formatStr) {
		c := formatStr[i]
		if c == '-' || c == '+' || c == ' ' || c == '#' || c == '0' {
			i++
			continue
		}
		break
	}

	// 解析宽度
	widthStart := i
	for i < len(formatStr) && formatStr[i] >= '0' && formatStr[i] <= '9' {
		i++
	}
	if widthStart < i {
		// 有宽度字段
		widthStr := formatStr[widthStart:i]
		if width, err := strconv.ParseInt(widthStr, 10, 64); err == nil {
			lengthMod = width
		}
	}

	// 解析精度
	if i < len(formatStr) && formatStr[i] == '.' {
		i++
		precisionStart := i
		for i < len(formatStr) && formatStr[i] >= '0' && formatStr[i] <= '9' {
			i++
		}
		if precisionStart < i {
			// 有精度字段
			precisionStr := formatStr[precisionStart:i]
			if precision, err := strconv.ParseInt(precisionStr, 10, 64); err == nil && precision > lengthMod {
				lengthMod = precision
			}
		}
	}

	// 解析长度修饰符
	if i+1 < len(formatStr) {
		twoChar := formatStr[i : i+2]
		if twoChar == "hd" || twoChar == "hi" || twoChar == "hu" || twoChar == "hz" {
			return twoChar, lengthMod, i + 2
		}
	}

	// 解析单个字符的长度修饰符
	if i < len(formatStr) {
		c := formatStr[i]
		if c == 'h' || c == 'l' || c == 'L' {
			i++
		}
	}

	// 解析转换说明符
	if i < len(formatStr) {
		specifier := "%" + string(formatStr[i])
		return specifier, lengthMod, i + 1
	}

	return "%", lengthMod, i
}

// estimateStringLength 估算字符串表达式的长度
func (d *FormatStringDetector) estimateStringLength(ctx *core.AnalysisContext, node *sitter.Node) int64 {
	if node == nil {
		return -1 // unknown
	}

	nodeType := core.SafeType(node)

	// 字符串字面量 - 精确长度
	if nodeType == "string_literal" {
		text := ctx.GetSourceText(node)
		if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
			content := text[1 : len(text)-1]
			// 处理转义字符
			length := 0
			i := 0
			for i < len(content) {
				if content[i] == '\\' && i+1 < len(content) {
					i += 2
				} else {
					i++
				}
				length++
			}
			return int64(length + 1) // +1 for null terminator
		}
	}

	// 标识符 - 查找缓冲区大小
	if nodeType == "identifier" {
		varName := ctx.GetSourceText(node)
		if size, ok := d.bufferSizes[varName]; ok {
			return size
		}
		return -1 // unknown
	}

	return -1 // unknown
}

// extractArgumentAtNew 提取指定索引的参数（避免与方法名冲突）
func (d *FormatStringDetector) extractArgumentAtNew(args *sitter.Node, index int) *sitter.Node {
	if args == nil || core.SafeType(args) != "argument_list" {
		return nil
	}

	currentIndex := 0
	for i := 0; i < int(core.SafeChildCount(args)); i++ {
		child := core.SafeChild(args, i)
		childType := core.SafeType(child)

		if childType == "," || childType == "(" || childType == ")" {
			continue
		}

		if currentIndex == index {
			return child
		}

		currentIndex++
	}

	return nil
}
