package detectors

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// CommandInjectionDetector 命令注入漏洞检测器 (CWE-78)
// 使用共享的污点分析引擎检测命令注入漏洞
type CommandInjectionDetector struct {
	*core.BaseDetector
	taintEngine *core.MemoryTaintEngine
}

// NewCommandInjectionDetector 创建新的命令注入检测器
func NewCommandInjectionDetector() *CommandInjectionDetector {
	return &CommandInjectionDetector{
		BaseDetector: core.NewBaseDetector(
			"command_injection",
			"Detects command injection vulnerabilities (CWE-78) using taint analysis",
		),
	}
}

// Name 返回检测器名称
func (d *CommandInjectionDetector) Name() string {
	return "Command Injection Detector"
}

// Description 返回检测器描述
func (d *CommandInjectionDetector) Description() string {
	return "Detects potential command injection vulnerabilities using taint analysis"
}

// Run 执行检测
func (d *CommandInjectionDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// *** 改进 ***: 初始化污点分析引擎并执行跨函数污点传播
	ctx.InitTaintEngine()
	if err := ctx.RunCrossFunctionTaintPropagation(); err != nil {
		// 跨函数污点传播失败不是致命错误，继续执行
		fmt.Printf("[Warning] Cross-function taint propagation failed: %v\n", err)
	}

	// 查找所有函数定义
	funcQuery := `(function_definition) @func`
	funcMatches, err := ctx.Query(funcQuery)
	if err != nil {
		return nil, err
	}

	// 对每个函数进行分析
	for _, funcMatch := range funcMatches {
		funcName := d.extractFuncName(ctx, funcMatch.Node)
		if funcName == "" {
			continue
		}

		// 分析函数内的命令执行函数调用
		d.analyzeCommandExecution(ctx, funcMatch.Node, funcName, &vulns)
	}

	return vulns, nil
}

// analyzeCommandExecution 分析命令执行
func (d *CommandInjectionDetector) analyzeCommandExecution(ctx *core.AnalysisContext, funcNode *sitter.Node, funcName string, vulns *[]core.DetectorVulnerability) {
	// 递归查找命令执行函数调用
	d.findCommandExecCalls(ctx, funcNode, funcName, vulns)
}

// findCommandExecCalls 查找命令执行函数调用
func (d *CommandInjectionDetector) findCommandExecCalls(ctx *core.AnalysisContext, node *sitter.Node, funcName string, vulns *[]core.DetectorVulnerability) {
	if node == nil {
		return
	}

	// 检查是否为命令执行函数调用
	if core.SafeType(node) == "call_expression" {
		d.checkCommandExecCall(ctx, node, funcName, vulns)
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.findCommandExecCalls(ctx, core.SafeChild(node, i), funcName, vulns)
	}
}

// checkCommandExecCall 检查命令执行函数调用
func (d *CommandInjectionDetector) checkCommandExecCall(ctx *core.AnalysisContext, callNode *sitter.Node, funcName string, vulns *[]core.DetectorVulnerability) {
	// 获取函数名
	funcNode := core.SafeChildByFieldName(callNode, "function")
	if funcNode == nil || core.SafeType(funcNode) != "identifier" {
		return
	}

	calleeName := strings.TrimSpace(ctx.GetSourceText(funcNode))

	// 检查是否为命令执行函数
	if !d.isCommandExecFunction(calleeName) {
		return
	}

	// 获取参数
	args := core.SafeChildByFieldName(callNode, "arguments")
	if args == nil {
		return
	}

	line := int(callNode.StartPoint().Row) + 1

	// 检查参数是否被污染
	if d.isCommandTainted(ctx, args, calleeName) {
		vuln := d.BaseDetector.CreateVulnerability(
			core.CWE78,
			fmt.Sprintf("Command injection vulnerability: user-controlled command at line %d in function %s", line, calleeName),
			callNode,
			core.ConfidenceHigh,
			core.SeverityHigh,
		)
		*vulns = append(*vulns, vuln)
	}
}

// isCommandTainted 检查命令参数是否被污染
func (d *CommandInjectionDetector) isCommandTainted(ctx *core.AnalysisContext, args *sitter.Node, funcName string) bool {
	if core.SafeChildCount(args) == 0 {
		return false
	}

	// system() 函数的第一个参数是要执行的命令
	if funcName == "system" || funcName == "popen" {
		// 检查第一个参数
		cmdArg := d.extractFirstArgument(args)
		if cmdArg == nil {
			return false
		}

		// 检查第一个参数是否为字符串字面量
		if core.SafeType(cmdArg) == "string_literal" {
			// 检查是否包含shell元字符
			cmdText := ctx.GetSourceText(cmdArg)
			if d.containsShellMetacharacters(cmdText) {
				// 即使是字面量，如果包含元字符也可能有风险
				// 但这里我们主要检查用户输入
				return false
			}
		}

		// 检查第一个参数是否为标识符（可能是变量）
		if core.SafeType(cmdArg) == "identifier" {
			varName := strings.TrimSpace(ctx.GetSourceText(cmdArg))
			// 使用改进的变量污点分析
			return d.isVariableTainted(varName, ctx, cmdArg)
		}

		// 检查第一个参数是否为更复杂的表达式
		if core.SafeType(cmdArg) == "binary_expression" ||
			core.SafeType(cmdArg) == "call_expression" ||
			core.SafeType(cmdArg) == "conditional_expression" {
			// 复杂表达式也可能包含用户输入
			return d.containsUserInput(ctx, cmdArg)
		}
	}

	// exec家族函数可能有多个参数
	if d.isExecFamilyFunction(funcName) {
		// 检查所有参数
		for i := 0; i < int(core.SafeChildCount(args)); i++ {
			arg := core.SafeChild(args, i)
			if core.SafeType(arg) != "(" && core.SafeType(arg) != "," && core.SafeType(arg) != ")" {
				if core.SafeType(arg) == "identifier" {
					varName := strings.TrimSpace(ctx.GetSourceText(arg))
					if d.isVariableTainted(varName, ctx, arg) {
						return true
					}
				} else if core.SafeType(arg) == "call_expression" {
					// 函数调用也可能包含用户输入
					if d.containsUserInput(ctx, arg) {
						return true
					}
				}
			}
		}
	}

	return false
}

// containsShellMetacharacters 检查字符串是否包含shell元字符
func (d *CommandInjectionDetector) containsShellMetacharacters(cmd string) bool {
	shellMetas := []string{
		";", "&", "|", "&&", "||",
		"`", "$(", "$(", "${",
		"<", ">", ">>", "<<",
		"*", "?", "[", "]",
		"!", "$", "\\",
		"'", "\"",
	}

	for _, meta := range shellMetas {
		if strings.Contains(cmd, meta) {
			return true
		}
	}
	return false
}

// extractFirstArgument 提取第一个实际参数
func (d *CommandInjectionDetector) extractFirstArgument(args *sitter.Node) *sitter.Node {
	if core.SafeType(args) == "argument_list" {
		// 查找第一个非标点符号的参数
		for i := 0; i < int(core.SafeChildCount(args)); i++ {
			child := core.SafeChild(args, i)
			childType := core.SafeType(child)

			// 跳过标点符号
			if childType == "," || childType == "(" || childType == ")" {
				continue
			}

			// 如果是parenthesized_expression，递归提取
			if childType == "parenthesized_expression" && core.SafeChildCount(child) > 0 {
				for j := 0; j < int(core.SafeChildCount(child)); j++ {
					grandChild := core.SafeChild(child, j)
					if core.SafeType(grandChild) != "(" && core.SafeType(grandChild) != ")" {
						return grandChild
					}
				}
			}

			return child
		}
	}
	return nil
}

// isVariableTainted 检查变量是否被污染（使用跨函数污点传播）
func (d *CommandInjectionDetector) isVariableTainted(varName string, ctx *core.AnalysisContext, node *sitter.Node) bool {
	// *** 改进 ***: 优先使用跨函数污点传播
	if ctx.Taint != nil && core.SafeType(node) == "identifier" {
		engine := ctx.Taint.(*core.MemoryTaintEngine)
		currentFuncName := ctx.GetContainingFunctionName(node)
		if currentFuncName != "" {
			if engine.IsIdentifierTaintedInFunction(node, currentFuncName) {
				return true
			}
		}
	}

	// 回退到原有的污点检查逻辑
	// 1. 检查变量是否从用户输入函数赋值
	if d.isAssignedFromUserInput(varName, ctx, node) {
		return true
	}

	// 2. 检查变量是否从另一个被污染的变量赋值
	if d.isCopiedFromTaintedVariable(varName, ctx, node) {
		return true
	}

	// 3. 检查变量是否是函数参数且可能来自用户输入
	if d.isFunctionParameterPotentiallyTainted(varName, ctx, node) {
		return true
	}

	return false
}

// isAssignedFromUserInput 检查变量是否被用户输入函数赋值
func (d *CommandInjectionDetector) isAssignedFromUserInput(varName string, ctx *core.AnalysisContext, node *sitter.Node) bool {
	funcNode := d.findFunctionDefinition(node)
	if funcNode == nil {
		return false
	}

	return d.searchAssignmentInFunction(ctx, funcNode, varName)
}

// findFunctionDefinition 查找节点所在的函数定义
func (d *CommandInjectionDetector) findFunctionDefinition(node *sitter.Node) *sitter.Node {
	parent := node.Parent()
	for parent != nil {
		if core.SafeType(parent) == "function_definition" {
			return parent
		}
		parent = parent.Parent()
	}
	return nil
}

// searchAssignmentInFunction 在函数内搜索赋值语句
func (d *CommandInjectionDetector) searchAssignmentInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, varName string) bool {
	body := core.SafeChildByFieldName(funcNode, "body")
	if body == nil {
		return false
	}

	var found bool
	d.findAssignmentRecursive(ctx, body, varName, &found)

	return found
}

// findAssignmentRecursive 递归查找赋值
func (d *CommandInjectionDetector) findAssignmentRecursive(ctx *core.AnalysisContext, node *sitter.Node, varName string, found *bool) {
	if node == nil || *found {
		return
	}

	if core.SafeType(node) == "expression_statement" {
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if core.SafeType(child) == "assignment_expression" {
				lhs := core.SafeChildByFieldName(child, "left")
				if lhs != nil && core.SafeType(lhs) == "identifier" {
					assignedVar := strings.TrimSpace(ctx.GetSourceText(lhs))
					if assignedVar == varName {
						rhs := core.SafeChildByFieldName(child, "right")
						if rhs != nil && core.SafeType(rhs) == "call_expression" {
							if d.isUserInputFunctionCall(ctx, rhs) {
								*found = true
								return
							}
						}
					}
				}
			} else if core.SafeType(child) == "call_expression" {
				if d.isUserInputFunctionCall(ctx, child) {
					args := core.SafeChildByFieldName(child, "arguments")
					if args != nil {
						if d.isVariablePassedAsArgument(ctx, args, varName) {
							*found = true
							return
						}
					}
				}
			}
		}
	}

	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.findAssignmentRecursive(ctx, core.SafeChild(node, i), varName, found)
		if *found {
			break
		}
	}
}

// isCopiedFromTaintedVariable 检查变量是否从另一个被污染的变量复制
func (d *CommandInjectionDetector) isCopiedFromTaintedVariable(varName string, ctx *core.AnalysisContext, node *sitter.Node) bool {
	funcNode := d.findFunctionDefinition(node)
	if funcNode == nil {
		return false
	}

	return d.searchStringCopyInFunction(ctx, funcNode, varName)
}

// searchStringCopyInFunction 在函数内搜索字符串复制
func (d *CommandInjectionDetector) searchStringCopyInFunction(ctx *core.AnalysisContext, funcNode *sitter.Node, varName string) bool {
	body := core.SafeChildByFieldName(funcNode, "body")
	if body == nil {
		return false
	}

	var found bool
	d.findStringCopyRecursive(ctx, body, varName, &found)

	return found
}

// findStringCopyRecursive 递归查找字符串复制
func (d *CommandInjectionDetector) findStringCopyRecursive(ctx *core.AnalysisContext, node *sitter.Node, varName string, found *bool) {
	if node == nil || *found {
		return
	}

	if core.SafeType(node) == "call_expression" {
		funcNode := core.SafeChildByFieldName(node, "function")
		if funcNode != nil && core.SafeType(funcNode) == "identifier" {
			funcName := strings.TrimSpace(ctx.GetSourceText(funcNode))
			// 检查是否是字符串复制函数
			stringFuncs := map[string]bool{
				"strcpy": true, "strcat": true, "strncpy": true,
				"snprintf": true, "sprintf": true, "strcpy_s": true,
			}
			if stringFuncs[funcName] {
				args := core.SafeChildByFieldName(node, "arguments")
				if args != nil {
					// 检查目标参数是否是我们要找的变量
					if d.isVariableInArguments(ctx, args, varName, 0) {
						// 检查源参数是否被污染
						if d.isSourceArgumentTainted(ctx, args) {
							*found = true
							return
						}
					}
				}
			}
		}
	}

	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.findStringCopyRecursive(ctx, core.SafeChild(node, i), varName, found)
		if *found {
			break
		}
	}
}

// isVariableInArguments 检查变量是否在参数列表的指定位置
func (d *CommandInjectionDetector) isVariableInArguments(ctx *core.AnalysisContext, args *sitter.Node, varName string, argIndex int) bool {
	var currentIndex int
	for i := 0; i < int(core.SafeChildCount(args)); i++ {
		child := core.SafeChild(args, i)
		if core.SafeType(child) != "(" && core.SafeType(child) != "," && core.SafeType(child) != ")" {
			if currentIndex == argIndex && core.SafeType(child) == "identifier" {
				if strings.TrimSpace(ctx.GetSourceText(child)) == varName {
					return true
				}
			}
			currentIndex++
		}
	}
	return false
}

// isSourceArgumentTainted 检查源参数是否被污染
func (d *CommandInjectionDetector) isSourceArgumentTainted(ctx *core.AnalysisContext, args *sitter.Node) bool {
	var currentIndex int
	for i := 0; i < int(core.SafeChildCount(args)); i++ {
		child := core.SafeChild(args, i)
		if core.SafeType(child) != "(" && core.SafeType(child) != "," && core.SafeType(child) != ")" {
			if currentIndex == 1 { // 源参数通常是第二个（索引1）
				if core.SafeType(child) == "identifier" {
					varName := strings.TrimSpace(ctx.GetSourceText(child))
					// 递归检查源变量是否被污染
					return d.isVariableTainted(varName, ctx, child)
				} else if core.SafeType(child) == "string_literal" {
					return false // 字符串字面量是安全的
				}
			}
			currentIndex++
		}
	}
	return false
}

// isFunctionParameterPotentiallyTainted 检查函数参数是否可能被污染
func (d *CommandInjectionDetector) isFunctionParameterPotentiallyTainted(varName string, ctx *core.AnalysisContext, node *sitter.Node) bool {
	funcNode := d.findFunctionDefinition(node)
	if funcNode == nil {
		return false
	}

	params := core.SafeChildByFieldName(funcNode, "parameters")
	if params == nil {
		return false
	}

	var found bool
	d.findParameterNames(ctx, params, varName, &found)

	return found
}

// findParameterNames 递归查找参数名
func (d *CommandInjectionDetector) findParameterNames(ctx *core.AnalysisContext, node *sitter.Node, targetVarName string, found *bool) {
	if node == nil || *found {
		return
	}

	if core.SafeType(node) == "identifier" {
		varName := strings.TrimSpace(ctx.GetSourceText(node))
		if varName == targetVarName {
			*found = true
			return
		}
	}

	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		d.findParameterNames(ctx, core.SafeChild(node, i), targetVarName, found)
		if *found {
			break
		}
	}
}

// isUserInputFunctionCall 检查函数调用是否是用户输入函数
func (d *CommandInjectionDetector) isUserInputFunctionCall(ctx *core.AnalysisContext, callNode *sitter.Node) bool {
	funcNode := core.SafeChildByFieldName(callNode, "function")
	if funcNode == nil || core.SafeType(funcNode) != "identifier" {
		return false
	}

	funcName := strings.TrimSpace(ctx.GetSourceText(funcNode))
	return d.isUserInputFunction(funcName)
}

// isVariablePassedAsArgument 检查变量是否作为参数传递
func (d *CommandInjectionDetector) isVariablePassedAsArgument(ctx *core.AnalysisContext, args *sitter.Node, varName string) bool {
	for i := 0; i < int(core.SafeChildCount(args)); i++ {
		arg := core.SafeChild(args, i)
		if core.SafeType(arg) == "identifier" {
			argName := strings.TrimSpace(ctx.GetSourceText(arg))
			if argName == varName {
				return true
			}
		}
	}
	return false
}

// containsUserInput 检查表达式是否包含用户输入
func (d *CommandInjectionDetector) containsUserInput(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 简化实现：假设所有非字面量的复杂表达式都可能包含用户输入
	return true
}

// isCommandExecFunction 检查是否为命令执行函数
func (d *CommandInjectionDetector) isCommandExecFunction(funcName string) bool {
	cmdFuncs := []string{
		"system", "popen", "pclose",
		"exec", "execl", "execle", "execlp", "execv", "execvp", "execvpe",
		"spawn", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
		"ShellExecute", "WinExec",
	}

	for _, fname := range cmdFuncs {
		if funcName == fname {
			return true
		}
	}
	return false
}

// isExecFamilyFunction 检查是否为exec家族函数
func (d *CommandInjectionDetector) isExecFamilyFunction(funcName string) bool {
	execFuncs := []string{
		"exec", "execl", "execle", "execlp", "execv", "execvp", "execvpe",
		"spawn", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
	}

	for _, fname := range execFuncs {
		if funcName == fname {
			return true
		}
	}
	return false
}

// isUserInputFunction 检查是否为用户输入函数
func (d *CommandInjectionDetector) isUserInputFunction(funcName string) bool {
	userInputFunctions := []string{
		"scanf", "gets", "getchar", "fgets", "fgetc",
		"read", "recv", "readline", "getenv",
		"fread", "getc", "getline",
	}

	for _, fname := range userInputFunctions {
		if funcName == fname {
			return true
		}
	}
	return false
}

// extractFuncName 提取函数名
func (d *CommandInjectionDetector) extractFuncName(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
	for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
		child := core.SafeChild(funcNode, i)
		if core.SafeType(child) == "function_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "identifier" {
					return ctx.GetSourceText(subChild)
				}
			}
		}
	}
	return ""
}
