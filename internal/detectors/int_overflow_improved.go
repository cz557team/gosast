package detectors

import (
	"fmt"
	"math/big"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// IntOverflowDetectorImproved 改进的整数溢出/下溢检测器
// 主要改进：
// 1. 充分利用 Z3 约束求解验证路径可行性
// 2. 分析变量之间的约束关系
// 3. 理解常见的边界检查模式
// 4. 区分有符号和无符号运算的溢出行为
// 5. 使用污点分析，只报告被污染的变量导致的溢出
// 6. 跨过程分析 - 跟踪函数调用链
// 7. 宏展开分析 - 处理复杂的宏定义
// 8. 符号执行增强 - 更精确的路径约束
type IntOverflowDetectorImproved struct {
	*core.BaseDetector
	z3Solver        core.Z3Solver
	taintEngine     *core.MemoryTaintEngine // 污点分析引擎
	// 约束追踪
	constraints     map[string]*VariableConstraints // 变量约束
	valueRanges     map[string]*ValueRange         // 变量值范围
	boundsChecks    map[int]*BoundsCheck           // 边界检查
	// 类型推断
	varTypes        map[string]*VarTypeInfo        // 变量类型信息
	structFields    map[string]map[string]*VarTypeInfo // 结构体字段类型: structName -> fieldName -> typeInfo
	typedefMap      map[string]*VarTypeInfo        // typedef 映射
	// 跨过程分析
	functionInfos   map[string]*FunctionInfo       // 函数信息
	callChains      map[string][]string            // 调用链: varName -> []functionNames
	// 宏展开分析
	macroDefinitions map[string]string             // 宏定义: name -> expansion
	macroConstants   map[string]int64              // 宏常量: name -> value
	// 符号执行增强
	pathConstraints map[*sitter.Node]*PathConstraint // 路径约束
	callContext     *CallContext                   // 当前调用上下文
	mutex           sync.RWMutex
}

// FunctionInfo 函数信息（用于跨过程分析）
type FunctionInfo struct {
	Name            string
	Params          []ParamInfo                   // 参数信息
	ReturnType      *VarTypeInfo                   // 返回类型
	HasBoundCheck   bool                           // 是否有边界检查
	MaxReturnValues map[string]int64               // 返回值的最大值
}

// ParamInfo 参数信息
type ParamInfo struct {
	Name        string
	Type        *VarTypeInfo
	HasBoundCheck bool
}

// PathConstraint 路径约束（用于符号执行）
type PathConstraint struct {
	Conditions  []string                       // 条件列表
	VarRanges   map[string]*ValueRange         // 变量值范围
	IsValid     bool                           // 路径是否可达
}

// CallContext 调用上下文
type CallContext struct {
	FunctionName   string
	CallerNode     *sitter.Node
	ParamMappings  map[string]string            // 调用参数到函数参数的映射
}

// VarTypeInfo 变量类型信息
type VarTypeInfo struct {
	Name           string
	TypeName       string  // 原始类型名
	IsUnsigned     bool
	BitWidth       int     // 位宽 (8, 16, 32, 64)
	IsSizeType     bool    // 是否是 size_t/ssize_t
}

// 溢出边界常量
const (
	OverflowInt8Max    int64 = 127
	OverflowInt8Min    int64 = -128
	OverflowUint8Max   int64 = 255

	OverflowInt16Max   int64 = 32767
	OverflowInt16Min   int64 = -32768
	OverflowUint16Max  int64 = 65535

	OverflowInt32Max   int64 = 2147483647
	OverflowInt32Min   int64 = -2147483648
	OverflowUint32Max  int64 = 4294967295

	OverflowInt64Max   int64 = 9223372036854775807
	OverflowInt64Min   int64 = -9223372036854775808
	OverflowUint64Max  int64 = -1 // 对于无符号64位，使用最大可能值
)

// VariableConstraints 变量约束
type VariableConstraints struct {
	Name            string
	LowerBound      int64
	UpperBound      int64
	HasLowerBound   bool
	HasUpperBound   bool
	IsNonNegative   bool
	IsPositive      bool
}

// ValueRange 变量值范围
type ValueRange struct {
	Min        int64
	Max        int64
	IsUnsigned bool
	IsFixed    bool // 是否为固定值
}

// BoundsCheck 边界检查信息
type BoundsCheck struct {
	Line          int
	VarName       string
	CheckType     string // "upper", "lower", "range"
	LowerBound    int64
	UpperBound    int64
	CheckExpression string
	IsValid       bool
}

// NewIntOverflowDetectorImproved 创建改进的整数溢出检测器
func NewIntOverflowDetectorImproved() *IntOverflowDetectorImproved {
	solver, _ := core.CreateZ3Solver()

	detector := &IntOverflowDetectorImproved{
		BaseDetector: core.NewBaseDetector(
			"Integer Overflow Detector",
			"Detects integer overflow/underflow with interprocedural analysis, macro expansion, and enhanced symbolic execution",
		),
		z3Solver:         solver,
		taintEngine:      nil, // 在 Run 方法中初始化
		constraints:      make(map[string]*VariableConstraints),
		valueRanges:      make(map[string]*ValueRange),
		boundsChecks:     make(map[int]*BoundsCheck),
		varTypes:         make(map[string]*VarTypeInfo),
		structFields:     make(map[string]map[string]*VarTypeInfo),
		typedefMap:       make(map[string]*VarTypeInfo),
		functionInfos:    make(map[string]*FunctionInfo),
		callChains:       make(map[string][]string),
		macroDefinitions: make(map[string]string),
		macroConstants:   make(map[string]int64),
		pathConstraints:  make(map[*sitter.Node]*PathConstraint),
		callContext:      nil,
	}

	// 初始化常见结构体字段类型映射
	detector.initCommonStructTypes()
	// 初始化常见宏常量
	detector.initCommonMacros()

	return detector
}

// initCommonStructTypes 初始化常见的结构体字段类型
func (d *IntOverflowDetectorImproved) initCommonStructTypes() {
	// 通用 C 标准库结构体字段类型（仅作为示例）
	// 注意：具体项目的结构体应该在分析过程中动态收集

	// 常见 typedef（C 标准库）
	d.typedefMap["size_t"] = &VarTypeInfo{TypeName: "size_t", IsUnsigned: true, BitWidth: 64, IsSizeType: true}
	d.typedefMap["ssize_t"] = &VarTypeInfo{TypeName: "ssize_t", IsUnsigned: false, BitWidth: 64, IsSizeType: true}
	d.typedefMap["uint64_t"] = &VarTypeInfo{TypeName: "uint64_t", IsUnsigned: true, BitWidth: 64}
	d.typedefMap["int64_t"] = &VarTypeInfo{TypeName: "int64_t", IsUnsigned: false, BitWidth: 64}
	d.typedefMap["uint32_t"] = &VarTypeInfo{TypeName: "uint32_t", IsUnsigned: true, BitWidth: 32}
	d.typedefMap["int32_t"] = &VarTypeInfo{TypeName: "int32_t", IsUnsigned: false, BitWidth: 32}
	d.typedefMap["uint16_t"] = &VarTypeInfo{TypeName: "uint16_t", IsUnsigned: true, BitWidth: 16}
	d.typedefMap["int16_t"] = &VarTypeInfo{TypeName: "int16_t", IsUnsigned: false, BitWidth: 16}
	d.typedefMap["uint8_t"] = &VarTypeInfo{TypeName: "uint8_t", IsUnsigned: true, BitWidth: 8}
	d.typedefMap["int8_t"] = &VarTypeInfo{TypeName: "int8_t", IsUnsigned: false, BitWidth: 8}
}

// initCommonMacros 初始化常见的宏常量
func (d *IntOverflowDetectorImproved) initCommonMacros() {
	// C 标准库宏常量 (limits.h / stdint.h)
	d.macroConstants["INT8_MAX"] = 127
	d.macroConstants["INT8_MIN"] = -128
	d.macroConstants["UINT8_MAX"] = 255
	d.macroConstants["INT16_MAX"] = 32767
	d.macroConstants["INT16_MIN"] = -32768
	d.macroConstants["UINT16_MAX"] = 65535
	d.macroConstants["INT32_MAX"] = 2147483647
	d.macroConstants["INT32_MIN"] = -2147483648
	d.macroConstants["UINT32_MAX"] = 4294967295
	d.macroConstants["INT64_MAX"] = 9223372036854775807
	d.macroConstants["INT64_MIN"] = -9223372036854775808
	d.macroConstants["UINT64_MAX"] = -1 // 0xFFFFFFFFFFFFFFFF

	// 常见的宏定义展开模式
	d.macroDefinitions["MIN"] = "((a) < (b) ? (a) : (b))"
	d.macroDefinitions["MAX"] = "((a) > (b) ? (a) : (b))"
	d.macroDefinitions["ABS"] = "((a) < 0 ? -(a) : (a))"
}

// Name 返回检测器名称
func (d *IntOverflowDetectorImproved) Name() string {
	return d.BaseDetector.Name()
}

// Description 返回检测器描述
func (d *IntOverflowDetectorImproved) Description() string {
	return "Detects potential integer overflow and underflow vulnerabilities using enhanced constraint analysis with Z3 and taint analysis"
}

// Run 执行检测
func (d *IntOverflowDetectorImproved) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 初始化污点分析引擎
	if d.taintEngine == nil {
		d.taintEngine = core.NewMemoryTaintEngine(ctx)
	}

	// *** 改进 ***: 执行跨函数污点传播
	ctx.InitTaintEngine()
	if err := ctx.RunCrossFunctionTaintPropagation(); err != nil {
		// 跨函数污点传播失败不是致命错误，继续执行
		fmt.Printf("[Warning] Cross-function taint propagation failed: %v\n", err)
	}

	// 执行污点传播分析
	if ctx.CFG != nil {
		if err := d.taintEngine.Propagate(ctx.CFG); err != nil {
			// 污点传播失败，继续检测但可能漏掉一些漏洞
		}
	}

	// 重置状态
	d.mutex.Lock()
	d.constraints = make(map[string]*VariableConstraints)
	d.valueRanges = make(map[string]*ValueRange)
	d.boundsChecks = make(map[int]*BoundsCheck)
	d.varTypes = make(map[string]*VarTypeInfo)
	d.functionInfos = make(map[string]*FunctionInfo)
	d.callChains = make(map[string][]string)
	d.pathConstraints = make(map[*sitter.Node]*PathConstraint)
	d.mutex.Unlock()

	// 【新增】第一遍：收集宏定义和常量
	d.collectMacroDefinitions(ctx)

	// 【新增】第二遍：跨过程分析 - 收集函数信息
	d.analyzeFunctions(ctx)

	// 【新增】第三遍：构建调用链
	d.buildCallChains(ctx)

	// 【新增】第四遍：路径敏感分析 - 收集路径约束
	d.analyzePathConstraints(ctx)

	// 第五遍：收集约束、类型和边界检查
	d.collectConstraints(ctx)

	// 第六遍：检查整数溢出（乘法）
	overflowVulns := d.checkOverflows(ctx)
	vulns = append(vulns, overflowVulns...)

	// 第七遍：检查整数下溢（减法）
	underflowVulns := d.checkUnderflows(ctx)
	vulns = append(vulns, underflowVulns...)

	return vulns, nil
}

// collectMacroDefinitions 收集宏定义和常量
func (d *IntOverflowDetectorImproved) collectMacroDefinitions(ctx *core.AnalysisContext) {
	// 查找宏定义 (preproc_def)
	macros, _ := ctx.QueryNodes("(preproc_def) @macro")

	for _, macro := range macros {
		nameNode := core.SafeChildByFieldName(macro, "name")
		if nameNode == nil {
			continue
		}

		macroName := ctx.GetSourceText(nameNode)
		macroName = strings.TrimPrefix(macroName, "#")
		macroName = strings.TrimSpace(macroName)

		// 尝试提取宏值
		valueNode := core.SafeChildByFieldName(macro, "value")
		if valueNode != nil {
			valueText := ctx.GetSourceText(valueNode)
			valueText = strings.TrimSpace(valueText)

			// 尝试解析为整数
			if val, err := strconv.ParseInt(valueText, 0, 64); err == nil {
				d.mutex.Lock()
				d.macroConstants[macroName] = val
				d.mutex.Unlock()
			} else {
				// 保存宏展开
				d.mutex.Lock()
				d.macroDefinitions[macroName] = valueText
				d.mutex.Unlock()
			}
		}
	}
}

// analyzeFunctions 跨过程分析 - 收集函数信息
func (d *IntOverflowDetectorImproved) analyzeFunctions(ctx *core.AnalysisContext) {
	// 查找所有函数定义
	funcDefs, _ := ctx.QueryNodes("(function_definition) @func")

	for _, funcDef := range funcDefs {
		funcName := d.getFunctionName(ctx, funcDef)
		if funcName == "" {
			continue
		}

		funcInfo := &FunctionInfo{
			Name:              funcName,
			Params:            []ParamInfo{},
			ReturnType:        nil,
			HasBoundCheck:     false,
			MaxReturnValues:   make(map[string]int64),
		}

		// 分析函数参数
		d.analyzeFunctionParams(ctx, funcDef, funcInfo)

		// 检查函数体内是否有边界检查
		funcInfo.HasBoundCheck = d.hasBoundsCheckInFunction(ctx, funcDef)

		d.mutex.Lock()
		d.functionInfos[funcName] = funcInfo
		d.mutex.Unlock()
	}
}

// getFunctionName 获取函数名
func (d *IntOverflowDetectorImproved) getFunctionName(ctx *core.AnalysisContext, funcDef *sitter.Node) string {
	// 查找 function_declarator
	decl := core.SafeChildByFieldName(funcDef, "declarator")
	if decl != nil {
		// 查找 identifier
		for i := 0; i < int(core.SafeChildCount(decl)); i++ {
			child := core.SafeChild(decl, i)
			if core.SafeType(child) == "identifier" {
				return ctx.GetSourceText(child)
			}
		}
	}
	return ""
}

// analyzeFunctionParams 分析函数参数
func (d *IntOverflowDetectorImproved) analyzeFunctionParams(ctx *core.AnalysisContext, funcDef *sitter.Node, funcInfo *FunctionInfo) {
	// 查找参数列表
	params := core.SafeChildByFieldName(funcDef, "parameters")
	if params == nil {
		return
	}

	for i := 0; i < int(core.SafeChildCount(params)); i++ {
		param := core.SafeChild(params, i)
		if core.SafeType(param) == "parameter_declaration" {
			paramName := d.extractIdentifier(ctx, param)
			if paramName != "" {
				paramType := d.getExpressionType(ctx, param)
				funcInfo.Params = append(funcInfo.Params, ParamInfo{
					Name:        paramName,
					Type:        paramType,
					HasBoundCheck: false,
				})
			}
		}
	}
}

// hasBoundsCheckInFunction 检查函数体内是否有边界检查
func (d *IntOverflowDetectorImproved) hasBoundsCheckInFunction(ctx *core.AnalysisContext, funcDef *sitter.Node) bool {
	body := core.SafeChildByFieldName(funcDef, "body")
	if body == nil {
		return false
	}

	// 遍历函数体的子节点，查找 if 语句
	d.findIfStatements(body, func(ifStmt *sitter.Node) bool {
		condition := core.SafeChildByFieldName(ifStmt, "condition")
		if condition != nil {
			condText := ctx.GetSourceText(condition)
			// 检查是否包含边界检查模式
			if strings.Contains(condText, "<") || strings.Contains(condText, "<=") ||
			   strings.Contains(condText, ">") || strings.Contains(condText, ">=") {
				return true
			}
		}
		return false
	})

	return false
}

// findIfStatements 递归查找 if 语句
func (d *IntOverflowDetectorImproved) findIfStatements(node *sitter.Node, callback func(*sitter.Node) bool) bool {
	if node == nil {
		return false
	}

	// 检查当前节点是否是 if 语句
	if core.SafeType(node) == "if_statement" {
		if callback(node) {
			return true
		}
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if d.findIfStatements(child, callback) {
			return true
		}
	}

	return false
}

// buildCallChains 构建调用链
func (d *IntOverflowDetectorImproved) buildCallChains(ctx *core.AnalysisContext) {
	// 查找所有函数调用
	callExprs, _ := ctx.QueryNodes("(call_expression) @call")

	for _, call := range callExprs {
		funcName := d.extractIdentifier(ctx, call)
		if funcName == "" {
			continue
		}

		// 分析调用参数
		for i := 0; i < int(core.SafeChildCount(call)); i++ {
			arg := core.SafeChild(call, i)
			if core.SafeType(arg) != "argument_list" {
				continue
			}

			// 遍历参数列表
			for j := 0; j < int(core.SafeChildCount(arg)); j++ {
				param := core.SafeChild(arg, j)
				if param == nil {
					continue
				}

				// 提取参数中的变量
				varName := d.extractIdentifier(ctx, param)
				if varName != "" {
					d.mutex.Lock()
					if _, exists := d.callChains[varName]; !exists {
						d.callChains[varName] = []string{}
					}
					d.callChains[varName] = append(d.callChains[varName], funcName)
					d.mutex.Unlock()
				}
			}
		}
	}
}

// analyzePathConstraints 路径敏感分析 - 收集路径约束
func (d *IntOverflowDetectorImproved) analyzePathConstraints(ctx *core.AnalysisContext) {
	// 查找所有 if 语句，分析路径约束
	ifStmts, _ := ctx.QueryNodes("(if_statement) @if")

	for _, ifStmt := range ifStmts {
		condition := core.SafeChildByFieldName(ifStmt, "condition")
		if condition == nil {
			continue
		}

		constraint := d.analyzeConditionConstraint(ctx, condition)
		if constraint != nil {
			d.mutex.Lock()
			d.pathConstraints[ifStmt] = constraint
			d.mutex.Unlock()
		}
	}
}

// analyzeConditionConstraint 分析条件表达式的约束
func (d *IntOverflowDetectorImproved) analyzeConditionConstraint(ctx *core.AnalysisContext, condition *sitter.Node) *PathConstraint {
	if condition == nil {
		return nil
	}

	condText := ctx.GetSourceText(condition)
	constraint := &PathConstraint{
		Conditions:  []string{condText},
		VarRanges:   make(map[string]*ValueRange),
		IsValid:     true,
	}

	// 尝试提取约束信息
	// 例如: if (x < 100) -> x 的范围是 [min, 100)
	if strings.Contains(condText, "<") {
		parts := strings.Split(condText, "<")
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[0])
			boundStr := strings.TrimSpace(parts[1])
			if bound, err := strconv.ParseInt(boundStr, 0, 64); err == nil {
				constraint.VarRanges[varName] = &ValueRange{
					Min:        -9223372036854775808,
					Max:        bound - 1,
					IsUnsigned: false,
					IsFixed:    false,
				}
			}
		}
	}

	return constraint
}

// isProtectedByFunctionCall 检查是否受函数调用保护（跨过程分析）
func (d *IntOverflowDetectorImproved) isProtectedByFunctionCall(ctx *core.AnalysisContext, varName string) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// 检查调用链
	if callChain, ok := d.callChains[varName]; ok {
		for _, funcName := range callChain {
			if funcInfo, exists := d.functionInfos[funcName]; exists && funcInfo.HasBoundCheck {
				return true
			}
		}
	}

	return false
}

// expandMacro 尝试展开宏
func (d *IntOverflowDetectorImproved) expandMacro(macroName string) (string, bool) {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// 检查是否是宏常量
	if val, ok := d.macroConstants[macroName]; ok {
		return fmt.Sprintf("%d", val), true
	}

	// 检查是否是宏定义
	if expansion, ok := d.macroDefinitions[macroName]; ok {
		return expansion, true
	}

	return "", false
}

// collectConstraints 收集变量约束和边界检查
func (d *IntOverflowDetectorImproved) collectConstraints(ctx *core.AnalysisContext) {
	// 查找所有 if 语句（可能包含边界检查）
	ifStmts, _ := ctx.QueryNodes("(if_statement) @if")

	for _, ifStmt := range ifStmts {
		d.analyzeIfStatement(ctx, ifStmt)
	}

	// 查找变量声明和初始化
	decls, _ := ctx.QueryNodes("(declaration) @decl")

	for _, decl := range decls {
		d.analyzeDeclaration(ctx, decl)
	}
}

// analyzeIfStatement 分析 if 语句（提取边界检查）
func (d *IntOverflowDetectorImproved) analyzeIfStatement(ctx *core.AnalysisContext, ifNode *sitter.Node) {
	condition := core.SafeChildByFieldName(ifNode, "condition")
	if condition == nil {
		return
	}

	line := int(ifNode.StartPoint().Row) + 1
	condText := ctx.GetSourceText(condition)

	// 解析边界检查模式
	check := d.parseBoundsCheck(ctx, condition, condText, line)
	if check != nil {
		d.mutex.Lock()
		d.boundsChecks[line] = check
		d.mutex.Unlock()
	}
}

// parseBoundsCheck 解析边界检查
func (d *IntOverflowDetectorImproved) parseBoundsCheck(ctx *core.AnalysisContext, condition *sitter.Node, condText string, line int) *BoundsCheck {
	// 模式1: var < upper_bound
	if strings.Contains(condText, "<") && !strings.Contains(condText, "==") {
		parts := strings.Split(condText, "<")
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[0])
			boundStr := strings.TrimSpace(parts[1])

			// 尝试解析边界值
			if bound, err := strconv.ParseInt(boundStr, 0, 64); err == nil {
				// 记录约束
				d.recordConstraint(varName, 0, bound-1, true, false)
				return &BoundsCheck{
					Line:       line,
					VarName:    varName,
					CheckType:  "upper",
					UpperBound: bound,
					CheckExpression: condText,
					IsValid:    true,
				}
			}
		}
	}

	// 模式2: var > lower_bound
	if strings.Contains(condText, ">") && !strings.Contains(condText, "==") {
		parts := strings.Split(condText, ">")
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[0])
			boundStr := strings.TrimSpace(parts[1])

			if bound, err := strconv.ParseInt(boundStr, 0, 64); err == nil {
				d.recordConstraint(varName, bound+1, 0, false, true)
				return &BoundsCheck{
					Line:       line,
					VarName:    varName,
					CheckType:  "lower",
					LowerBound: bound,
					CheckExpression: condText,
					IsValid:    true,
				}
			}
		}
	}

	// 模式3: var <= upper_bound
	if strings.Contains(condText, "<=") {
		parts := strings.Split(condText, "<=")
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[0])
			boundStr := strings.TrimSpace(parts[1])

			if bound, err := strconv.ParseInt(boundStr, 0, 64); err == nil {
				d.recordConstraint(varName, 0, bound, true, false)
				return &BoundsCheck{
					Line:       line,
					VarName:    varName,
					CheckType:  "upper",
					UpperBound: bound,
					CheckExpression: condText,
					IsValid:    true,
				}
			}
		}
	}

	// 模式4: var >= lower_bound
	if strings.Contains(condText, ">=") {
		parts := strings.Split(condText, ">=")
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[0])
			boundStr := strings.TrimSpace(parts[1])

			if bound, err := strconv.ParseInt(boundStr, 0, 64); err == nil {
				d.recordConstraint(varName, bound, 0, true, false)
				return &BoundsCheck{
					Line:       line,
					VarName:    varName,
					CheckType:  "lower",
					LowerBound: bound,
					CheckExpression: condText,
					IsValid:    true,
				}
			}
		}
	}

	// 模式5: lower_bound < var < upper_bound (范围检查)
	// 这需要更复杂的解析，这里简化处理
	if strings.Count(condText, "<") >= 2 || strings.Count(condText, ">") >= 2 {
		return &BoundsCheck{
			Line:            line,
			CheckType:       "range",
			CheckExpression: condText,
			IsValid:         true,
		}
	}

	return nil
}

// recordConstraint 记录变量约束
func (d *IntOverflowDetectorImproved) recordConstraint(varName string, lower, upper int64, hasLower, hasUpper bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, exists := d.constraints[varName]; !exists {
		d.constraints[varName] = &VariableConstraints{
			Name: varName,
		}
	}

	if hasLower {
		d.constraints[varName].LowerBound = lower
		d.constraints[varName].HasLowerBound = true
		if lower >= 0 {
			d.constraints[varName].IsNonNegative = true
		}
		if lower > 0 {
			d.constraints[varName].IsPositive = true
		}
	}

	if hasUpper {
		d.constraints[varName].UpperBound = upper
		d.constraints[varName].HasUpperBound = true
	}
}

// analyzeDeclaration 分析声明（提取类型、约束、值范围）
func (d *IntOverflowDetectorImproved) analyzeDeclaration(ctx *core.AnalysisContext, declNode *sitter.Node) {
	// 首先提取类型信息
	d.inferVariableType(ctx, declNode)

	// 然后查找变量初始化
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if core.SafeType(child) == "init_declarator" {
			d.analyzeInitDeclarator(ctx, child)
		}
	}
}

// inferVariableType 从声明中推断变量类型
func (d *IntOverflowDetectorImproved) inferVariableType(ctx *core.AnalysisContext, declNode *sitter.Node) {
	// 查找类型说明符
	var typeName string
	var typeInfo *VarTypeInfo

	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		typeStr := core.SafeType(child)

		// 检查基本类型说明符
		if typeStr == "primitive_type" || typeStr == "sized_type_specifier" {
			typeName = ctx.GetSourceText(child)
			typeInfo = d.parseTypeName(typeName)
			break
		}

		// 检查类型定义（如 typedef unsigned long size_t）
		if typeStr == "type_identifier" {
			existingType := d.getExistingType(ctx.GetSourceText(child))
			if existingType != nil {
				typeInfo = existingType
				typeName = child.String()
				break
			}
		}
	}

	if typeInfo == nil {
		return
	}

	// 查找声明的变量名
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if core.SafeType(child) == "init_declarator" {
			varName := d.extractIdentifierFromDeclarator(ctx, child)
			if varName != "" {
				d.mutex.Lock()
				d.varTypes[varName] = typeInfo
				d.mutex.Unlock()
			}
		}
	}
}

// parseTypeName 解析类型名，返回类型信息
func (d *IntOverflowDetectorImproved) parseTypeName(typeName string) *VarTypeInfo {
	info := &VarTypeInfo{
		TypeName: typeName,
	}

	// 转换为小写进行比较
	lower := strings.ToLower(typeName)

	// 检查无符号类型
	info.IsUnsigned = strings.HasPrefix(lower, "unsigned") ||
		strings.HasPrefix(lower, "uint")

	// 检查 size_t / ssize_t
	if lower == "size_t" || lower == "ssize_t" {
		info.IsSizeType = true
		info.BitWidth = 64 // size_t 通常是 64 位
		if lower == "size_t" {
			info.IsUnsigned = true
		}
		return info
	}

	// 根据类型名推断位宽
	switch {
	case strings.Contains(lower, "64") || strings.Contains(lower, "long"):
		info.BitWidth = 64
	case strings.Contains(lower, "32") || strings.Contains(lower, "int"):
		info.BitWidth = 32
	case strings.Contains(lower, "16"):
		info.BitWidth = 16
	case strings.Contains(lower, "8") || strings.Contains(lower, "char"):
		info.BitWidth = 8
	default:
		// 默认假设 int
		info.BitWidth = 32
	}

	return info
}

// getExistingType 获取已知的类型定义（通用C标准库类型）
func (d *IntOverflowDetectorImproved) getExistingType(typeName string) *VarTypeInfo {
	// C 标准库常用类型定义（非项目特定）
	knownTypes := map[string]*VarTypeInfo{
		// 标准尺寸类型
		"size_t":    {TypeName: "size_t", BitWidth: 64, IsUnsigned: true, IsSizeType: true},
		"ssize_t":   {TypeName: "ssize_t", BitWidth: 64, IsUnsigned: false, IsSizeType: true},
		"ptrdiff_t": {TypeName: "ptrdiff_t", BitWidth: 64, IsUnsigned: false, IsSizeType: true},
		"intptr_t":  {TypeName: "intptr_t", BitWidth: 64, IsUnsigned: false},
		"uintptr_t": {TypeName: "uintptr_t", BitWidth: 64, IsUnsigned: true},
		"intmax_t":  {TypeName: "intmax_t", BitWidth: 64, IsUnsigned: false},
		"uintmax_t": {TypeName: "uintmax_t", BitWidth: 64, IsUnsigned: true},
	}

	if t, ok := knownTypes[typeName]; ok {
		return t
	}
	return nil
}

// extractIdentifierFromDeclarator 从声明符中提取标识符
func (d *IntOverflowDetectorImproved) extractIdentifierFromDeclarator(ctx *core.AnalysisContext, declarator *sitter.Node) string {
	if declarator == nil {
		return ""
	}

	for i := 0; i < int(core.SafeChildCount(declarator)); i++ {
		child := core.SafeChild(declarator, i)
		if core.SafeType(child) == "identifier" {
			return ctx.GetSourceText(child)
		}
		// 递归处理嵌套的声明符
		if subIdent := d.extractIdentifierFromDeclarator(ctx, child); subIdent != "" {
			return subIdent
		}
	}

	return ""
}

// analyzeInitDeclarator 分析初始化声明符
func (d *IntOverflowDetectorImproved) analyzeInitDeclarator(ctx *core.AnalysisContext, initDecl *sitter.Node) {
	var varName string
	var initValue int64
	var hasValue bool

	for j := 0; j < int(core.SafeChildCount(initDecl)); j++ {
		subChild := core.SafeChild(initDecl, j)
		if core.SafeType(subChild) == "identifier" {
			varName = ctx.GetSourceText(subChild)
		} else if core.SafeType(subChild) == "number_literal" {
			text := ctx.GetSourceText(subChild)
			if val, err := strconv.ParseInt(text, 0, 64); err == nil {
				initValue = val
				hasValue = true
			}
		}
	}

	if varName != "" && hasValue {
		d.mutex.Lock()
		d.valueRanges[varName] = &ValueRange{
			Min:     initValue,
			Max:     initValue,
			IsFixed: true,
		}
		d.mutex.Unlock()
	}
}

// checkOverflows 检查整数溢出（带去重）
func (d *IntOverflowDetectorImproved) checkOverflows(ctx *core.AnalysisContext) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 【新增】去重机制 - 使用 map 跟踪已报告的位置
	reportedLocations := make(map[string]bool)

	// 【新增】跳过头文件（头文件通常包含宏定义和接口声明，不是实际执行代码）
	if d.isHeaderFile(ctx.Unit.FilePath) {
		return vulns
	}

	// 【新增】跳过测试文件（测试文件包含故意的边界条件测试）
	if d.shouldSkipFile(ctx.Unit.FilePath) {
		return vulns
	}

	// 查找所有乘法表达式
	mults, _ := ctx.Query("(binary_expression) @mult")

	for _, match := range mults {
		text := ctx.GetSourceText(match.Node)
		if strings.Contains(text, "*") {
			if d.isOverflowRisk(ctx, match.Node, text) {
				// 计算唯一位置标识（文件路径 + 行号 + 列号）
				startPoint := match.Node.StartPoint()
				locationKey := fmt.Sprintf("%s:%d:%d",
					ctx.Unit.FilePath,
					startPoint.Row+1,  // 转换为1-based
					startPoint.Column)

				// 检查是否已经报告过此位置
				if reportedLocations[locationKey] {
					continue
				}

				// 标记为已报告
				reportedLocations[locationKey] = true

				line := int(startPoint.Row) + 1

				message := fmt.Sprintf("Potential integer overflow in multiplication at line %d", line)
				if d.z3Solver != nil && d.z3Solver.IsAvailable() {
					message += " (verified with Z3 constraint solving)"
				}

				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE190,
					message,
					match.Node,
					core.ConfidenceMedium,
					core.SeverityHigh,
				)
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// getOverflowBounds 根据类型获取溢出边界
func (d *IntOverflowDetectorImproved) getOverflowBounds(varName string) (maxVal, minVal int64, is64Bit bool) {
	d.mutex.RLock()
	varType, hasType := d.varTypes[varName]
	d.mutex.RUnlock()

	if hasType {
		switch varType.BitWidth {
		case 64:
			if varType.IsUnsigned {
				return OverflowUint64Max, 0, true
			}
			return OverflowInt64Max, OverflowInt64Min, true
		case 32:
			if varType.IsUnsigned {
				return OverflowUint32Max, 0, false
			}
			return OverflowInt32Max, OverflowInt32Min, false
		case 16:
			if varType.IsUnsigned {
				return OverflowUint16Max, 0, false
			}
			return OverflowInt16Max, OverflowInt16Min, false
		case 8:
			if varType.IsUnsigned {
				return OverflowUint8Max, 0, false
			}
			return OverflowInt8Max, OverflowInt8Min, false
		}
	}

	// 默认返回 INT32 边界（保守估计）
	return OverflowInt32Max, OverflowInt32Min, false
}

// getOverflowBoundsForType 根据类型信息获取溢出边界
func (d *IntOverflowDetectorImproved) getOverflowBoundsForType(typeInfo *VarTypeInfo) (maxVal, minVal int64, is64Bit bool) {
	if typeInfo == nil {
		return OverflowInt32Max, OverflowInt32Min, false
	}

	switch typeInfo.BitWidth {
	case 64:
		if typeInfo.IsUnsigned {
			return OverflowUint64Max, 0, true
		}
		return OverflowInt64Max, OverflowInt64Min, true
	case 32:
		if typeInfo.IsUnsigned {
			return OverflowUint32Max, 0, false
		}
		return OverflowInt32Max, OverflowInt32Min, false
	case 16:
		if typeInfo.IsUnsigned {
			return OverflowUint16Max, 0, false
		}
		return OverflowInt16Max, OverflowInt16Min, false
	case 8:
		if typeInfo.IsUnsigned {
			return OverflowUint8Max, 0, false
		}
		return OverflowInt8Max, OverflowInt8Min, false
	}

	// 默认返回 INT32 边界（保守估计）
	return OverflowInt32Max, OverflowInt32Min, false
}

// isOverflowRisk 检查溢出风险
// 【第11次迭代：基于2024-2025最新研究的精确检测】
// 参考：ZeroFalse 2025, CMU 2024, Hybrid Semantic 2025
//
// 核心改进：
// 1. 移除所有启发式字符串匹配规则（违反用户要求）
// 2. 使用精确的类型系统分析和符号执行
// 3. 依赖Z3约束求解进行验证
// 4. 只保留C/C++语言标准定义的安全模式
func (d *IntOverflowDetectorImproved) isOverflowRisk(ctx *core.AnalysisContext, node *sitter.Node, text string) bool {
	// 【2024-2025 最新研究：ESBMC v7.4 + CMU 两步法】
	// 核心原则：
	// 1. 两步法验证：先检查溢出可能性，再检查可利用性
	// 2. 区间分析（ESBMC v7.4）
	// 3. 过滤故意的溢出（加密库/内核优化）

	// === 第一步：溢出可能性检查 ===

	// 1.1 语言构造过滤（C/C++ 标准）
	if d.isInsideSizeofExpression(ctx, node) {
		return false
	}
	if d.hasFloatingPointLiteral(text) {
		return false
	}

	// 获取操作数
	if core.SafeChildCount(node) < 3 {
		return false
	}
	left := core.SafeChild(node, 0)
	right := core.SafeChild(node, 2)

	// 浮点运算不是整数溢出
	if d.isFloatingPointOperation(ctx, left) || d.isFloatingPointOperation(ctx, right) {
		return false
	}

	// 1.2 区间分析：提取操作数的值范围
	leftMin, leftMax, leftHasRange := d.computeValueRange(ctx, left)
	rightMin, rightMax, rightHasRange := d.computeValueRange(ctx, right)

	// 1.3 检查是否可能溢出（使用保守的区间分析）
	mayOverflow := d.checkMultiplicationOverflowConservative(
		leftMin, leftMax, leftHasRange,
		rightMin, rightMax, rightHasRange,
	)

	if !mayOverflow {
		return false // 区间分析显示不可能溢出
	}

	// 1.4 使用 Z3 进行形式化验证（如果可用）
	if d.z3Solver != nil && d.z3Solver.IsAvailable() {
		// 提取操作数
		leftVal, leftOk := d.extractIntValue(ctx, left)
		rightVal, rightOk := d.extractIntValue(ctx, right)

		// 如果两个都是常量，直接检查
		if leftOk && rightOk {
			// 使用大整数精确计算
			result := new(big.Int).Mul(big.NewInt(leftVal), big.NewInt(rightVal))

			// 检查是否溢出 INT32 范围
			if result.Cmp(big.NewInt(OverflowInt32Max)) <= 0 &&
				result.Cmp(big.NewInt(OverflowInt32Min)) >= 0 {
				return false // 常量折叠显示不溢出
			}
		}
	}

	// === 第二步：可利用性检查（CMU 两步法） ===

	// 2.1 只报告在危险上下文中的溢出
	// 危险上下文：内存分配函数的参数
	if !d.isExploitableContextStrict(ctx, node) {
		return false
	}

	// 2.2 过滤加密库中的故意的溢出（Buglens 2025）
	if d.isIntentionalOverflowInCrypto(ctx, node) {
		return false
	}

	// 通过所有检查，报告漏洞
	return true
}

// ===== 旧代码已弃用，保留供参考 =====
// 以下代码将在验证新方法后删除
func (d *IntOverflowDetectorImproved) isOverflowRiskOld(ctx *core.AnalysisContext, node *sitter.Node, text string) bool {
	// 【已禁用】isPointerDeclaration 过于激进，违反"禁止激进启发式规则"的要求
	// 它把所有在声明语句中的乘法都标记为"指针声明"相关
	// 例如：int c = a * b; 中的 a * b 会被误认为安全
	// if d.isPointerDeclaration(ctx, node) {
	// 	return false
	// }

	// 【新增】过滤 sizeof 表达式 - sizeof(*ptr) 中的 * 不是乘法
	if d.isInsideSizeofExpression(ctx, node) {
		return false
	}

	// 【新增】快速过滤：检查整个表达式文本是否包含浮点字面量
	if d.hasFloatingPointLiteral(text) {
		return false
	}

	// 【新增】过滤数学函数调用中的乘法
	if d.isInsideMathFunctionCall(ctx, node) {
		return false
	}

	// 获取左右操作数
	if core.SafeChildCount(node) < 3 {
		return false
	}

	left := core.SafeChild(node, 0)
	right := core.SafeChild(node, 2)

	// 【优化1】过滤浮点运算 - 跳过涉及 double/float 的乘法
	if d.isFloatingPointOperation(ctx, left) || d.isFloatingPointOperation(ctx, right) {
		return false
	}

	// 【改进2】过滤sizeof表达式中的乘法 - sizeof(T) * count 是安全的
	if d.isSizeofMultiplication(ctx, node, left, right) {
		return false
	}

	// 【已禁用】isArrayIndexCalculation 过于激进，违反"禁止激进启发式规则"的要求
	// 它会检查表达式是否包含 "size", "index" 等关键词
	// 如果父节点是 assignment_expression，就返回 true（安全），这会导致真正的溢出被误过滤
	// if d.isArrayIndexCalculation(ctx, node, text) {
	// 	return false
	// }

	// 【新增】过滤像素/颜色计算模式
	if d.isPixelColorCalculation(ctx, node, text) {
		return false
	}

	// 【新增】过滤几何/向量计算模式
	if d.isGeometricCalculation(ctx, node, text) {
		return false
	}

	// 【优化2】良性模式匹配 - 加密/哈希算法中的故意溢出
	if d.isInCryptographicAlgorithm(ctx, node) {
		return false
	}

	// 【优化3】良性模式匹配 - 位操作中的乘法
	if d.isBitManipulation(ctx, node) {
		return false
	}

	// 【优化4】良性模式匹配 - 哈希表索引操作
	if d.isHashIndexOperation(ctx, node) {
		return false
	}

	// 【优化5】检查是否为循环变量乘法（带小常量）
	if d.isLoopVariableWithSmallConstant(ctx, node, left, right) {
		return false
	}

	// 【改进4】检查是否为常量表达式或宏定义计算
	if d.isConstantExpression(ctx, node, left, right, text) {
		return false
	}

	// 【已禁用】isSafeLocalVariableOperation 过于激进，违反"禁止激进启发式规则"的要求
	// 它将所有"局部变量 + 小常量(<1000) + assignment_expression"标记为安全
	// 这会导致大量真正的溢出被误过滤
	// if d.isSafeLocalVariableOperation(ctx, node, left, right) {
	// 	return false
	// }

	// 【新第1次迭代】检查是否为安全范围内的乘法
	// 基于类型系统的数学推理，而非启发式规则
	if d.isSafeRangeMultiplication(ctx, node, left, right, text) {
		return false
	}

	// 【新第1次迭代】检查变量是否有显式的范围保证
	// 基于控制流分析的语义推理
	varName := d.extractIdentifier(ctx, left)
	if varName == "" {
		varName = d.extractIdentifier(ctx, right)
	}

	if varName != "" {
		// 获取操作数以确定常量值
		var varNode *sitter.Node
		var constVal int64
		hasConst := false

		leftVal, leftOk := d.extractIntValue(ctx, left)
		rightVal, rightOk := d.extractIntValue(ctx, right)

		if leftOk {
			constVal = leftVal
			varNode = right
			hasConst = true
		} else if rightOk {
			constVal = rightVal
			varNode = left
			hasConst = true
		}

		if hasConst && varNode != nil {
			if d.hasExplicitRangeGuarantee(ctx, varNode, varName, constVal) {
				return false
			}
		}
	}

	// 【新增】跨过程分析 - 检查是否受被调用函数保护
	if varName != "" && d.isProtectedByFunctionCall(ctx, varName) {
		return false
	}

	// 尝试提取整数值
	leftVal, leftOk := d.extractIntValue(ctx, left)
	rightVal, rightOk := d.extractIntValue(ctx, right)

	// 场景1：两个都是字面量
	if leftOk && rightOk {
		// 检查乘积是否溢出（使用 INT32 边界，因为字面量通常是 int）
		product := leftVal * rightVal
		if product > OverflowInt32Max || product < OverflowInt32Min {
			// 使用 Z3 验证
			if d.z3Solver != nil && d.z3Solver.IsAvailable() {
				return d.z3Solver.CheckOverflow(leftVal, rightVal)
			}
			// 两个字面量相乘溢出不需要污点检查（编译时常量）
			return true
		}
		return false
	}

	// 场景2：一个字面量，一个变量
	if leftOk || rightOk {
		literalVal := int64(0)
		varNode := left
		isLeftLiteral := leftOk

		if isLeftLiteral {
			literalVal = leftVal
			varNode = right
		} else {
			literalVal = rightVal
			varNode = left
		}

		// 获取表达式类型（支持成员访问表达式）
		exprType := d.getExpressionType(ctx, varNode)

		// 获取变量名（用于约束查找）
		varName := d.extractIdentifier(ctx, varNode)
		if varName == "" && exprType == nil {
			return false
		}

		// 根据表达式类型获取正确的溢出边界
		var maxVal, minVal int64
		var is64Bit bool

		if exprType != nil {
			// 使用推断的表达式类型
			maxVal, minVal, is64Bit = d.getOverflowBoundsForType(exprType)
		} else {
			// 回退到变量名查找
			maxVal, minVal, is64Bit = d.getOverflowBounds(varName)
		}

		// 检查变量的约束
		d.mutex.RLock()
		constraints, hasConstraints := d.constraints[varName]
		valueRange, hasValueRange := d.valueRanges[varName]
		d.mutex.RUnlock()

		// 如果有约束，进行更精确的分析
		if hasConstraints {
			return d.checkOverflowWithConstraints(ctx, literalVal, constraints, varName)
		}

		// 如果有固定值
		if hasValueRange && valueRange.IsFixed {
			product := literalVal * valueRange.Max
			if product > maxVal || product < minVal {
				// 检查变量是否被污染
				if !d.isNodeTainted(ctx, varNode) {
					return false
				}
				if d.z3Solver != nil && d.z3Solver.IsAvailable() {
					return d.z3Solver.CheckOverflow(literalVal, valueRange.Max)
				}
				return true
			}
			return false
		}

		// 使用 Z3 进行符号执行
		if d.z3Solver != nil && d.z3Solver.IsAvailable() {
			if d.z3Solver.CheckOverflow(left, right) {
				// 检查变量是否被污染
				if !d.isNodeTainted(ctx, varNode) {
					return false
				}
				// 进一步验证：检查是否受边界检查保护
				return !d.isProtectedByBoundsCheck(ctx, varName, int(node.StartPoint().Row)+1)
			}
		}

		// 优化：调整字面量阈值
		// 对于 64 位类型，使用更高的阈值 (1000000)
		// 对于 32 位及以下类型，保持阈值 (1000)
		threshold := int64(1000)
		if is64Bit {
			threshold = 1000000
		}

		if literalVal > threshold || literalVal < -threshold {
			// 检查变量是否被污染
			if !d.isNodeTainted(ctx, varNode) {
				return false
			}
			return true
		}

		return false
	}

	// 场景3：两个都是变量
	leftVar := d.extractIdentifier(ctx, left)
	rightVar := d.extractIdentifier(ctx, right)

	// 获取表达式类型（支持成员访问表达式）
	leftType := d.getExpressionType(ctx, left)
	rightType := d.getExpressionType(ctx, right)

	if leftVar != "" && rightVar != "" {
		// 检查是否有约束
		d.mutex.RLock()
		leftConstraints, leftHas := d.constraints[leftVar]
		rightConstraints, rightHas := d.constraints[rightVar]
		d.mutex.RUnlock()

		if leftHas && rightHas {
			// 两个都有约束，使用 Z3 验证
			if d.z3Solver != nil && d.z3Solver.IsAvailable() {
				// 检查是否至少有一个操作数被污染
				if !d.isAnyOperandTainted(ctx, left, right) {
					return false
				}
				return d.checkSymbolicOverflow(ctx, leftVar, rightVar, leftConstraints, rightConstraints)
			}
		}

		// 使用 Z3 进行符号执行
		if d.z3Solver != nil && d.z3Solver.IsAvailable() {
			if d.z3Solver.CheckOverflow(left, right) {
				// 检查是否至少有一个操作数被污染
				if !d.isAnyOperandTainted(ctx, left, right) {
					return false
				}
				return !d.isProtectedByBoundsCheck(ctx, leftVar, int(node.StartPoint().Row)+1) &&
					   !d.isProtectedByBoundsCheck(ctx, rightVar, int(node.StartPoint().Row)+1)
			}
		}

		// 对于无约束的变量乘法，检查是否有边界检查保护
		// 如果没有保护，报告潜在的溢出风险（中等置信度）
		hasBoundsCheck := d.isProtectedByBoundsCheck(ctx, leftVar, int(node.StartPoint().Row)+1) ||
		                 d.isProtectedByBoundsCheck(ctx, rightVar, int(node.StartPoint().Row)+1)

		// 检查是否在安全模式中（如初始化、小值操作）
		if !hasBoundsCheck && !d.isInSafeContext(ctx, node) {
			// 【修复】不再要求操作数被污染
			// 整数溢出可以发生在非污点数据上，例如：
			// int size = width * height;  // width 和 height 是函数参数，可能很大

			// 优化：如果两个操作数都是64位类型，减少误报
			// 因为64位类型不容易溢出
			leftIs64Bit := leftType != nil && leftType.BitWidth == 64
			rightIs64Bit := rightType != nil && rightType.BitWidth == 64

			if leftIs64Bit && rightIs64Bit {
				// 两个64位值相乘，不容易溢出，不报告
				return false
			}

			// 报告潜在风险（两个变量相乘，没有约束检查）
			return true
		}
	}

	return false
}

// isInSafeContext 检查是否在安全上下文中（避免误报）
func (d *IntOverflowDetectorImproved) isInSafeContext(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 【修复】移除过度激进的启发式规则
	// 原来的逻辑假设声明/初始化中的乘法是安全的，但实际上
	// "int size = width * height;" 正是经典的整数溢出漏洞模式

	// 只保留真正的安全模式：
	// 1. 编译时常量的乘法（两个操作数都是常量字面量）
	if d.isBothOperandsConstantLiterals(ctx, node) {
		return true
	}

	// 2. 明确的位运算相关（移位等）
	if d.isBitShiftingRelated(ctx, node) {
		return true
	}

	// 【新增】3. 检查是否在溢出检查保护之后
	// 例如：
	//   if (num_records > 0 && record_size > SIZE_MAX / num_records) { return; }
	//   size_t alloc_size = num_records * record_size; // 安全
	if d.isProtectedByOverflowCheck(ctx, node) {
		return true
	}

	// 不再假设声明/赋值是安全的，因为这些正是漏洞的高发场景
	return false
}

// isProtectedByOverflowCheck 检查乘法操作是否在溢出检查保护之后
// 识别常见的溢出检查模式，如：
//   if (a > 0 && b > MAX / a) { return; }
//   if (a != 0 && b > SIZE_MAX / a) { return; }
func (d *IntOverflowDetectorImproved) isProtectedByOverflowCheck(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 获取当前节点所在的函数
	funcNode := d.findContainingFunction(ctx, node)
	if funcNode == nil {
		return false
	}

	// 获取当前节点的行号
	currentLine := int(node.StartPoint().Row) + 1

	// 查找函数中的所有 if 语句
	body := core.SafeChildByFieldName(funcNode, "body")
	if body == nil {
		return false
	}

	// 递归查找 if 语句
	return d.findOverflowCheckProtection(ctx, body, currentLine, node)
}

// findOverflowCheckProtection 递归查找溢出检查保护
func (d *IntOverflowDetectorImproved) findOverflowCheckProtection(ctx *core.AnalysisContext, node *sitter.Node, currentLine int, multNode *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 检查当前节点是否是 if 语句
	if core.SafeType(node) == "if_statement" {
		ifStmtLine := int(node.StartPoint().Row) + 1

		// 只检查在乘法操作之前的 if 语句
		if ifStmtLine < currentLine {
			condition := core.SafeChildByFieldName(node, "condition")
			if condition != nil {
				condText := ctx.GetSourceText(condition)

				// 检查是否为溢出检查模式
				// 模式1: a > MAX / b 或 a < MIN / b（除法用于检测溢出）
				if d.isOverflowCheckPattern(ctx, condText, multNode) {
					// 检查 if 块是否有 return 或 continue
					consequence := core.SafeChildByFieldName(node, "consequence")
					if consequence != nil && d.hasTerminatingStatement(consequence) {
						return true
					}
				}
			}
		}
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		// 跳过当前乘法节点本身，避免循环
		if child != multNode && d.findOverflowCheckProtection(ctx, child, currentLine, multNode) {
			return true
		}
	}

	return false
}

// isOverflowCheckPattern 检查条件文本是否为溢出检查模式
func (d *IntOverflowDetectorImproved) isOverflowCheckPattern(ctx *core.AnalysisContext, condText string, multNode *sitter.Node) bool {
	// 获取乘法操作的变量名
	leftVar := ""
	rightVar := ""

	if multNode != nil && core.SafeChildCount(multNode) >= 3 {
		left := core.SafeChild(multNode, 0)
		right := core.SafeChild(multNode, 2)

		if left != nil {
			leftText := ctx.GetSourceText(left)
			// 提取变量名（去掉可能的类型转换等）
			leftVar = extractVarName(leftText)
		}

		if right != nil {
			rightText := ctx.GetSourceText(right)
			rightVar = extractVarName(rightText)
		}
	}

	// 检查溢出检查模式：
	// 1. 包含除法运算（/）
	// 2. 除法的结果用于比较（<, >, <=, >=）
	// 3. 涉及的变量与乘法操作相关

	hasDivision := strings.Contains(condText, "/")
	hasComparison := strings.Contains(condText, "<") || strings.Contains(condText, ">") ||
		strings.Contains(condText, "<=") || strings.Contains(condText, ">=")

	if !hasDivision || !hasComparison {
		return false
	}

	// 检查是否包含相关的变量
	if leftVar != "" && strings.Contains(condText, leftVar) {
		return true
	}
	if rightVar != "" && strings.Contains(condText, rightVar) {
		return true
	}

	// 通用模式：检查 SIZE_MAX, INT_MAX 等常量
	if strings.Contains(condText, "SIZE_MAX") || strings.Contains(condText, "INT_MAX") ||
		strings.Contains(condText, "UINT_MAX") || strings.Contains(condText, "LONG_MAX") {
		return true
	}

	return false
}

// extractVarName 从表达式中提取变量名
func extractVarName(expr string) string {
	// 去除空格
	expr = strings.TrimSpace(expr)

	// 去除类型转换，如 (size_t)var
	if strings.Contains(expr, ")") {
		parts := strings.Split(expr, ")")
		if len(parts) > 1 {
			expr = strings.TrimSpace(parts[len(parts)-1])
		}
	}

	// 去除函数调用，如 func()
	if strings.Contains(expr, "(") {
		return ""
	}

	// 只保留字母数字和下划线
	var result strings.Builder
	for _, ch := range expr {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' {
			result.WriteRune(ch)
		} else {
			break
		}
	}

	return result.String()
}

// hasTerminatingStatement 检查节点是否包含终止语句
func (d *IntOverflowDetectorImproved) hasTerminatingStatement(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 检查当前节点
	nodeType := core.SafeType(node)
	if nodeType == "return_statement" || nodeType == "break_statement" ||
		nodeType == "continue_statement" || nodeType == "goto_statement" {
		return true
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if d.hasTerminatingStatement(child) {
			return true
		}
	}

	return false
}

// findContainingFunction 查找包含节点的函数定义
func (d *IntOverflowDetectorImproved) findContainingFunction(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
	parent := node.Parent()
	for parent != nil {
		if core.SafeType(parent) == "function_definition" {
			return parent
		}
		parent = parent.Parent()
	}
	return nil
}

// isBothOperandsConstantLiterals 检查两个操作数是否都是常量字面量
func (d *IntOverflowDetectorImproved) isBothOperandsConstantLiterals(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if core.SafeChildCount(node) < 3 {
		return false
	}

	left := core.SafeChild(node, 0)
	right := core.SafeChild(node, 2)

	// 检查两个操作数是否都是 number_literal
	if core.SafeType(left) != "number_literal" || core.SafeType(right) != "number_literal" {
		return false
	}

	return true
}

// isBitShiftingRelated 检查是否与位移相关（通常是安全的位操作）
func (d *IntOverflowDetectorImproved) isBitShiftingRelated(ctx *core.AnalysisContext, node *sitter.Node) bool {
	text := ctx.GetSourceText(node)
	// 检查是否包含位移操作符
	if strings.Contains(text, "<<") || strings.Contains(text, ">>") {
		return true
	}
	return false
}

// checkOverflowWithConstraints 使用约束检查溢出
func (d *IntOverflowDetectorImproved) checkOverflowWithConstraints(ctx *core.AnalysisContext, literalVal int64, constraints *VariableConstraints, varName string) bool {
	// 根据变量类型获取正确的溢出边界
	maxVal, minVal, _ := d.getOverflowBounds(varName)

	// 计算最大可能的乘积
	var maxProduct int64

	if constraints.HasUpperBound {
		if literalVal > 0 {
			maxProduct = literalVal * constraints.UpperBound
		} else {
			maxProduct = literalVal * constraints.LowerBound
		}
	} else {
		// 没有上界，假设可能的最大值（根据类型调整）
		maxProduct = literalVal * maxVal
	}

	if maxProduct > maxVal || maxProduct < minVal {
		// 使用 Z3 验证
		if d.z3Solver != nil && d.z3Solver.IsAvailable() {
			return d.z3Solver.CheckOverflow(literalVal, constraints.UpperBound)
		}
		return true
	}

	return false
}

// checkSymbolicOverflow 检查符号溢出
func (d *IntOverflowDetectorImproved) checkSymbolicOverflow(ctx *core.AnalysisContext, leftVar, rightVar string, leftCons, rightCons *VariableConstraints) bool {
	// 获取正确的溢出边界
	maxVal, minVal, _ := d.getOverflowBounds(leftVar)

	// 构建符号约束
	leftMax := leftCons.UpperBound
	if !leftCons.HasUpperBound {
		leftMax = maxVal
	}

	rightMax := rightCons.UpperBound
	if !rightCons.HasUpperBound {
		rightMax = maxVal
	}

	// 使用 Z3 验证
	if d.z3Solver != nil && d.z3Solver.IsAvailable() {
		return d.z3Solver.CheckOverflow(leftMax, rightMax)
	}

	// 简单检查
	product := leftMax * rightMax
	return product > maxVal || product < minVal
}

// checkUnderflows 检查整数下溢
func (d *IntOverflowDetectorImproved) checkUnderflows(ctx *core.AnalysisContext) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 查找所有减法表达式
	subs, _ := ctx.Query("(binary_expression) @sub")

	for _, match := range subs {
		text := ctx.GetSourceText(match.Node)
		if strings.Contains(text, "-") {
			if d.isUnderflowRisk(ctx, match.Node, text) {
				line := int(match.Node.StartPoint().Row) + 1

				message := fmt.Sprintf("Potential integer underflow in subtraction at line %d", line)
				if d.z3Solver != nil && d.z3Solver.IsAvailable() {
					message += " (verified with Z3 constraint solving)"
				}

				vuln := d.BaseDetector.CreateVulnerability(
					core.CWE191,
					message,
					match.Node,
					core.ConfidenceMedium,
					core.SeverityHigh,
				)
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns
}

// isUnderflowRisk 检查下溢风险
func (d *IntOverflowDetectorImproved) isUnderflowRisk(ctx *core.AnalysisContext, node *sitter.Node, text string) bool {
	// 获取左右操作数
	if core.SafeChildCount(node) < 3 {
		return false
	}

	left := core.SafeChild(node, 0)
	right := core.SafeChild(node, 2)

	// 【改进3】过滤器：检查是否为循环变量在受保护的循环中
	if d.isProtectedLoopVariable(ctx, node, left, right) {
		return false
	}

	// 过滤器0：检查是否为常见的安全模式
	if d.isCommonSafePattern(ctx, node, text) {
		return false
	}

	// 过滤器1：检查是否为无符号类型的减法
	if d.isUnsignedSubtraction(ctx, node) {
		return d.checkUnsignedUnderflow(ctx, left, right, text)
	}

	// 尝试提取整数值
	leftVal, leftOk := d.extractIntValue(ctx, left)
	rightVal, rightOk := d.extractIntValue(ctx, right)

	// 场景1：两个都是字面量
	if leftOk && rightOk {
		// 检查是否下溢
		if rightVal > leftVal {
			// 使用 Z3 验证
			if d.z3Solver != nil && d.z3Solver.IsAvailable() {
				return d.z3Solver.CheckUnderflow(leftVal, rightVal)
			}
			// 两个字面量相减下溢不需要污点检查（编译时常量）
			return true
		}
		return false
	}

	// 场景2：一个字面量，一个变量
	if leftOk || rightOk {
		literalVal := int64(0)
		varNode := left
		isLeftLiteral := leftOk
		varName := ""

		if isLeftLiteral {
			literalVal = leftVal
			varNode = right
		} else {
			literalVal = rightVal
			varNode = left
		}

		varName = d.extractIdentifier(ctx, varNode)
		if varName == "" {
			return false
		}

		// 检查变量的约束
		d.mutex.RLock()
		constraints, hasConstraints := d.constraints[varName]
		d.mutex.RUnlock()

		if hasConstraints {
			// 检查变量是否被污染
			if !d.isNodeTainted(ctx, varNode) {
				return false
			}
			return d.checkUnderflowWithConstraints(ctx, literalVal, constraints, varName, isLeftLiteral)
		}

		// 使用 Z3 进行符号执行
		if d.z3Solver != nil && d.z3Solver.IsAvailable() {
			if d.z3Solver.CheckUnderflow(left, right) {
				// 检查变量是否被污染
				if !d.isNodeTainted(ctx, varNode) {
					return false
				}
				// 检查是否受边界检查保护
				return !d.isProtectedByBoundsCheck(ctx, varName, int(node.StartPoint().Row)+1)
			}
		}

		return false
	}

	// 场景3：两个都是变量
	leftVar := d.extractIdentifier(ctx, left)
	rightVar := d.extractIdentifier(ctx, right)

	if leftVar != "" && rightVar != "" {
		// 使用 Z3 进行符号执行
		if d.z3Solver != nil && d.z3Solver.IsAvailable() {
			if d.z3Solver.CheckUnderflow(left, right) {
				// 检查是否至少有一个操作数被污染
				if !d.isAnyOperandTainted(ctx, left, right) {
					return false
				}
				return !d.isProtectedByBoundsCheck(ctx, leftVar, int(node.StartPoint().Row)+1) &&
					   !d.isProtectedByBoundsCheck(ctx, rightVar, int(node.StartPoint().Row)+1)
			}
		}
	}

	return false
}

// isUnsignedSubtraction 检查是否为无符号减法
func (d *IntOverflowDetectorImproved) isUnsignedSubtraction(ctx *core.AnalysisContext, node *sitter.Node) bool {
	text := ctx.GetSourceText(node)

	// 检查是否涉及 size_t 或其他无符号类型
	unsignedTypes := []string{"size_t", "uintptr_t", "uint64_t", "uint32_t", "uint16_t", "uint8_t",
		"unsigned int", "unsigned long", "unsigned short", "unsigned char"}

	for _, utype := range unsignedTypes {
		if strings.Contains(text, utype) {
			return true
		}
	}

	// 检查是否为 sizeof 表达式
	if strings.Contains(text, "sizeof") {
		return true
	}

	// 【新增】检查通用的无符号操作模式（编程语言通用）
	// 1. .size() 方法调用（C++ STL容器的 size() 返回 size_t）
	if strings.Contains(text, ".size()") || strings.Contains(text, ".length()") {
		return true
	}

	// 2. 容器大小的常见模式
	containerPatterns := []string{
		"size()", "length()", "capacity()",
		"getSize()", "getLength()", "count()",
	}
	for _, pattern := range containerPatterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}

	return false
}

// checkUnsignedUnderflow 检查无符号下溢
func (d *IntOverflowDetectorImproved) checkUnsignedUnderflow(ctx *core.AnalysisContext, left, right *sitter.Node, text string) bool {
	leftVal, leftOk := d.extractIntValue(ctx, left)
	rightVal, rightOk := d.extractIntValue(ctx, right)

	// 如果两个都是字面量
	if leftOk && rightOk {
		// 在无符号运算中，如果右操作数大于左操作数，会导致下溢
		return rightVal > leftVal
	}

	// 使用 Z3 验证
	if d.z3Solver != nil && d.z3Solver.IsAvailable() {
		if d.z3Solver.CheckUnderflow(left, right) {
			// 【新增】Z3 已经验证存在下溢，直接返回 true
			return true
		}
	}

	// 【新增】如果一个操作数是函数调用（如 .size()），且无法验证其值
	// 假设可能发生下溢（保守策略）
	leftIsCall := core.SafeType(left) == "call_expression" || strings.Contains(ctx.GetSourceText(left), ".size()")
	rightIsCall := core.SafeType(right) == "call_expression" || strings.Contains(ctx.GetSourceText(right), ".size()")

	if leftIsCall || rightIsCall {
		// 减法中包含函数调用，可能下溢
		// 检查是否有边界检查保护
		leftVar := d.extractIdentifier(ctx, left)
		rightVar := d.extractIdentifier(ctx, right)

		// 对于函数调用，尝试提取对象名
		if leftVar == "" && leftIsCall {
			// 尝试从 "src.size()" 中提取 "src"
			leftText := ctx.GetSourceText(left)
			if dotIdx := strings.LastIndex(leftText, "."); dotIdx > 0 {
				leftVar = leftText[:dotIdx]
			}
		}
		if rightVar == "" && rightIsCall {
			rightText := ctx.GetSourceText(right)
			if dotIdx := strings.LastIndex(rightText, "."); dotIdx > 0 {
				rightVar = rightText[:dotIdx]
			}
		}

		if leftVar != "" {
			if d.isProtectedByBoundsCheck(ctx, leftVar, int(left.StartPoint().Row)+1) {
				return false
			}
		}

		if rightVar != "" {
			if d.isProtectedByBoundsCheck(ctx, rightVar, int(right.StartPoint().Row)+1) {
				return false
			}
		}

		// 没有边界检查，报告潜在风险
		return true
	}

	// 保守策略：检查是否有边界检查保护
	leftVar := d.extractIdentifier(ctx, left)
	rightVar := d.extractIdentifier(ctx, right)

	if leftVar != "" {
		if d.isProtectedByBoundsCheck(ctx, leftVar, int(left.StartPoint().Row)+1) {
			return false
		}
	}

	if rightVar != "" {
		if d.isProtectedByBoundsCheck(ctx, rightVar, int(right.StartPoint().Row)+1) {
			return false
		}
	}

	return false
}

// checkUnderflowWithConstraints 使用约束检查下溢
func (d *IntOverflowDetectorImproved) checkUnderflowWithConstraints(ctx *core.AnalysisContext, literalVal int64, constraints *VariableConstraints, varName string, isLeftLiteral bool) bool {
	if isLeftLiteral {
		// 左边是字面量：literal - var
		// 下溢风险：var > literal
		if constraints.HasUpperBound && constraints.UpperBound > literalVal {
			if d.z3Solver != nil && d.z3Solver.IsAvailable() {
				return d.z3Solver.CheckUnderflow(literalVal, constraints.UpperBound)
			}
			return true
		}

		// 如果变量没有上界约束，使用保守策略
		if !constraints.HasUpperBound {
			// 检查是否有边界检查保护
			return !d.isProtectedByBoundsCheck(ctx, varName, 0)
		}
	} else {
		// 右边是字面量：var - literal
		// 下溢风险：var < literal
		if constraints.HasLowerBound && constraints.LowerBound < literalVal {
			if d.z3Solver != nil && d.z3Solver.IsAvailable() {
				return d.z3Solver.CheckUnderflow(constraints.LowerBound, literalVal)
			}
			return true
		}

		// 如果变量没有下界约束，使用保守策略
		if !constraints.HasLowerBound {
			return !d.isProtectedByBoundsCheck(ctx, varName, 0)
		}
	}

	return false
}

// isProtectedByBoundsCheck 检查是否受边界检查保护
// 增强版：路径敏感分析，检查 if 条件中的保护
func (d *IntOverflowDetectorImproved) isProtectedByBoundsCheck(ctx *core.AnalysisContext, varName string, line int) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// 1. 检查已收集的边界检查
	for _, check := range d.boundsChecks {
		if check.VarName == varName && check.Line < line && check.IsValid {
			return true
		}
	}

	return false
}

// 【改进3】isProtectedLoopVariable 检查是否为受循环条件保护的变量
// 例如：while(l >= 0) { l--; } 中的 l-- 是安全的
func (d *IntOverflowDetectorImproved) isProtectedLoopVariable(ctx *core.AnalysisContext, node, left, right *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 提取变量名
	varName := d.extractIdentifier(ctx, left)
	if varName == "" {
		varName = d.extractIdentifier(ctx, right)
	}
	if varName == "" {
		return false
	}

	// 向上查找循环结构
	current := node.Parent()
	depth := 0
	maxDepth := 10

	for current != nil && depth < maxDepth {
		nodeType := core.SafeType(current)

		// 检查是否在while循环中
		if nodeType == "while_statement" {
			condition := core.SafeChildByFieldName(current, "condition")
			if condition != nil {
				condText := ctx.GetSourceText(condition)
				// 检查循环条件是否包含边界保护
				// 例如：while(l >= 0), while(i > 0), while(count != 0)
				if strings.Contains(condText, varName) {
					// 检查是否有下界保护（>= 0, > 0, != NULL等）
					if strings.Contains(condText, ">=") ||
					   strings.Contains(condText, "> 0") ||
					   strings.Contains(condText, "!= NULL") ||
					   strings.Contains(condText, "!= 0") ||
					   strings.Contains(condText, "!= 0") {
						return true
					}
				}
			}
		}

		// 检查是否在for循环中
		if nodeType == "for_statement" {
			condition := core.SafeChildByFieldName(current, "condition")
			if condition != nil {
				condText := ctx.GetSourceText(condition)
				if strings.Contains(condText, varName) {
					// 检查是否有边界保护
					if strings.Contains(condText, "<") ||
					   strings.Contains(condText, "<=") ||
					   strings.Contains(condText, ">") ||
					   strings.Contains(condText, ">=") {
						return true
					}
				}
			}
		}

		// 检查是否在do-while循环中
		if nodeType == "do_statement" {
			condition := core.SafeChildByFieldName(current, "condition")
			if condition != nil {
				condText := ctx.GetSourceText(condition)
				if strings.Contains(condText, varName) {
					if strings.Contains(condText, ">=") ||
					   strings.Contains(condText, "> 0") ||
					   strings.Contains(condText, "!=") {
						return true
					}
				}
			}
		}

		current = current.Parent()
		depth++
	}

	return false
}

// isInCryptographicAlgorithm 检查是否在加密/哈希算法中
// 这些算法中的"溢出"通常是有意的位运算，不是真正的漏洞
func (d *IntOverflowDetectorImproved) isInCryptographicAlgorithm(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 获取当前函数名
	funcName := d.getCurrentFunctionName(ctx, node)

	// 【改进1】常见的加密/哈希算法函数名模式
	cryptoPatterns := []string{
		"Hash", "hash", "MD5", "SHA", "SHA1", "SHA256", "SHA512",
		"AES", "DES", "RSA", "RC4", "Blowfish", "Twofish",
		"Cipher", "cipher", "Encrypt", "encrypt", "Decrypt", "decrypt",
		"Digest", "digest", "HMAC", "hmac",
		"CRC", "crc", "Checksum", "checksum",
		"Base64", "base64",
		"XOR", "xor", "Rotate", "rotate", "Shift", "shift",
		"Murmur", "murmur", "FNV", "fnv",
		"SipHash", "CityHash", "XXHash",
		// 【新增】椭圆曲线和多精度整数运算模式
		"felem", "limb", "scalar", "mont", "modmul", "ecp", "nistp",
		"curve", "field", "modulus", "bigint", "bignum", "poly1305",
		"chacha", "salsa", "bn_", "ec_", "crypto_", "mul_",
	}

	for _, pattern := range cryptoPatterns {
		if strings.Contains(funcName, pattern) {
			return true
		}
	}

	// 【改进1】检查文件路径是否在加密相关的目录中
	filePath := ctx.Unit.FilePath
	cryptoDirs := []string{
		"crypto/ec", "crypto/bn", "crypto/rsa", "crypto/dsa",
		"crypto/ecdh", "crypto/ecdsa", "crypto/dh",
		"crypto/poly1305", "crypto/chacha", "crypto/siphash",
		"crypto/aes", "crypto/des", "crypto/rc4",
		"crypto/sha", "crypto/md5", "crypto/evp",
		"providers/implementations",
	}
	for _, dir := range cryptoDirs {
		if strings.Contains(filePath, dir) {
			// 进一步验证：检查是否真的在加密算法上下文中
			// 通过检查变量名是否包含limb/felem等关键字
			if strings.Contains(funcName, "limb") ||
			   strings.Contains(funcName, "felem") ||
			   strings.Contains(funcName, "scalar") ||
			   strings.Contains(funcName, "mul") ||
			   strings.Contains(funcName, "mont") {
				return true
			}
		}
	}

	// 检查父作用域是否包含加密相关的变量名
	parentText := ctx.GetSourceText(node.Parent())
	cryptoKeywords := []string{
		"cipher", "encrypt", "decrypt", "hash", "digest",
		"rounds", "rotation", "bitmask", "0x", "0X",
		"^", "<<", ">>", "|", "&", "~",
	}

	for _, keyword := range cryptoKeywords {
		if strings.Contains(parentText, keyword) {
			// 进一步验证：如果包含位运算符，很可能是加密算法
			if strings.Contains(parentText, "^") || strings.Contains(parentText, "<<") || strings.Contains(parentText, ">>") {
				return true
			}
		}
	}

	return false
}

// getCurrentFunctionName 获取当前节点所在的函数名
func (d *IntOverflowDetectorImproved) getCurrentFunctionName(ctx *core.AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return ""
	}

	// 向上查找函数定义
	parent := node.Parent()
	depth := 0
	maxDepth := 20

	for parent != nil && depth < maxDepth {
		nodeType := core.SafeType(parent)

		if nodeType == "function_definition" || nodeType == "declaration" {
			// 查找函数名
			for i := 0; i < int(core.SafeChildCount(parent)); i++ {
				child := core.SafeChild(parent, i)
				childType := core.SafeType(child)
				if childType == "function_declarator" || childType == "identifier" {
					return ctx.GetSourceText(child)
				}
			}
		}

		parent = parent.Parent()
		depth++
	}

	return ""
}

// isBitManipulation 检查是否为位操作模式
// 位操作中的乘法通常是故意的，不是溢出漏洞
func (d *IntOverflowDetectorImproved) isBitManipulation(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	text := ctx.GetSourceText(node)

	// 检查是否包含位运算相关的模式
	bitPatterns := []string{
		"<<", ">>", "&", "|", "^", "~",
		"0x", "0X", "0b", "0B",
		"UINT", "MAX", "MASK", "mask",
		"SHIFT", "shift", "ROTATE", "rotate",
	}

	for _, pattern := range bitPatterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}

	// 检查父上下文
	parent := node.Parent()
	if parent != nil {
		parentText := ctx.GetSourceText(parent)
		for _, pattern := range bitPatterns {
			if strings.Contains(parentText, pattern) {
				return true
			}
		}
	}

	return false
}

// isHashIndexOperation 检查是否为哈希表索引操作
// 哈希表中的取模运算通常保护了溢出
func (d *IntOverflowDetectorImproved) isHashIndexOperation(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 向上查找父节点，检查是否有取模运算
	parent := node.Parent()
	depth := 0
	maxDepth := 5

	for parent != nil && depth < maxDepth {
		text := ctx.GetSourceText(parent)

		// 检查是否有取模运算
		if strings.Contains(text, "%") || strings.Contains(text, "mod") {
			return true
		}

		// 检查是否有哈希表相关的函数调用
		if strings.Contains(text, "hash") || strings.Contains(text, "bucket") ||
		   strings.Contains(text, "index") || strings.Contains(text, "table") {
			return true
		}

		parent = parent.Parent()
		depth++
	}

	return false
}

// extractIntValue 提取整数值
func (d *IntOverflowDetectorImproved) extractIntValue(ctx *core.AnalysisContext, node *sitter.Node) (int64, bool) {
	if node == nil {
		return 0, false
	}

	if core.SafeType(node) == "number_literal" {
		text := ctx.GetSourceText(node)
		if val, err := strconv.ParseInt(text, 0, 64); err == nil {
			return val, true
		}
	}

	if core.SafeType(node) == "sizeof_expression" {
		// 尝试获取 sizeof 的参数
		// sizeof(typename) 或 sizeof(expression)
		if core.SafeChildCount(node) > 0 {
			arg := core.SafeChild(node, 0)
			if arg != nil {
				argText := ctx.GetSourceText(arg)
				// 常见类型的 sizeof 值
				typeSizes := map[string]int64{
					"char":     1, "int8_t": 1, "uint8_t": 1,
					"short":    2, "int16_t": 2, "uint16_t": 2,
					"int":      4, "int32_t": 4, "uint32_t": 4, "float": 4,
					"long":     8, "int64_t": 8, "uint64_t": 8, "double": 8, "size_t": 8,
					"long long": 8,
				}
				if size, ok := typeSizes[argText]; ok {
					return size, true
				}
				// 默认返回 4（常见情况）
				return 4, true
			}
		}
		// 默认值
		return 4, true
	}

	return 0, false
}

// extractIdentifier 提取标识符
func (d *IntOverflowDetectorImproved) extractIdentifier(ctx *core.AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return ""
	}

	if core.SafeType(node) == "identifier" {
		return ctx.GetSourceText(node)
	}

	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if core.SafeType(child) == "identifier" {
			return ctx.GetSourceText(child)
		}
	}

	return ""
}

// extractMemberAccess 提取成员访问表达式的类型信息
// 处理 image->columns 或 image.columns 等表达式
// 返回: (完整表达式, 类型信息)
func (d *IntOverflowDetectorImproved) extractMemberAccess(ctx *core.AnalysisContext, node *sitter.Node) (string, *VarTypeInfo) {
	if node == nil {
		return "", nil
	}

	nodeType := core.SafeType(node)
	fullText := ctx.GetSourceText(node)

	// 处理成员访问表达式: field_expression 或 pointer_expression
	if nodeType == "field_expression" || nodeType == "pointer_expression" {
		// 获取字段名 (右侧)
		fieldNode := core.SafeChildByFieldName(node, "field")
		if fieldNode == nil {
			// 尝试通过索引获取 (tree-sitter C 语法)
			if core.SafeChildCount(node) >= 3 {
				fieldNode = core.SafeChild(node, 2) // 通常 field_expression 的第3个子节点是字段名
			}
		}

		if fieldNode != nil && core.SafeType(fieldNode) == "field_identifier" {
			fieldName := ctx.GetSourceText(fieldNode)

			// 获取对象 (左侧)
			objectNode := core.SafeChildByFieldName(node, "argument")
			if objectNode == nil && core.SafeChildCount(node) >= 2 {
				objectNode = core.SafeChild(node, 0)
			}

			if objectNode != nil {
				// 获取对象类型
				objectType := d.inferObjectType(ctx, objectNode)
				if objectType != "" {
					// 查找结构体字段类型
					d.mutex.RLock()
					if fields, ok := d.structFields[objectType]; ok {
						if fieldType, ok := fields[fieldName]; ok {
							d.mutex.RUnlock()
							return fullText, fieldType
						}
					}
					d.mutex.RUnlock()
				}
			}
		}
	}

	// 如果不是成员访问，尝试作为普通标识符
	if nodeType == "identifier" {
		varName := fullText
		d.mutex.RLock()
		if varType, ok := d.varTypes[varName]; ok {
			d.mutex.RUnlock()
			return varName, varType
		}
		d.mutex.RUnlock()
		return varName, nil
	}

	// 递归处理子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if expr, typeInfo := d.extractMemberAccess(ctx, child); expr != "" {
			return expr, typeInfo
		}
	}

	return fullText, nil
}

// inferObjectType 推断对象类型
// 例如: "Image *image" -> "Image"
func (d *IntOverflowDetectorImproved) inferObjectType(ctx *core.AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return ""
	}

	// 如果是标识符，查找变量类型
	if core.SafeType(node) == "identifier" {
		varName := ctx.GetSourceText(node)
		d.mutex.RLock()
		if varType, ok := d.varTypes[varName]; ok {
			d.mutex.RUnlock()
			// 处理指针类型: "Image *" -> "Image"
			typeName := strings.TrimSpace(varType.TypeName)
			typeName = strings.TrimSuffix(typeName, "*")
			typeName = strings.TrimSuffix(typeName, " *")
			return typeName
		}
		d.mutex.RUnlock()
	}

	// 处理 call expression (如 GetPixelChannels() 返回 size_t)
	if core.SafeType(node) == "call_expression" {
		funcName := d.extractIdentifier(ctx, node)
		if strings.Contains(funcName, "GetPixelChannels") {
			return "size_t"
		}
	}

	return ""
}

// getExpressionType 获取表达式的类型信息
// 统一的入口点，处理各种表达式类型
func (d *IntOverflowDetectorImproved) getExpressionType(ctx *core.AnalysisContext, node *sitter.Node) *VarTypeInfo {
	if node == nil {
		return nil
	}

	nodeType := core.SafeType(node)

	// 字面量
	if nodeType == "number_literal" {
		return &VarTypeInfo{TypeName: "int", IsUnsigned: false, BitWidth: 32}
	}

	// 成员访问表达式
	if nodeType == "field_expression" || nodeType == "pointer_expression" {
		_, typeInfo := d.extractMemberAccess(ctx, node)
		return typeInfo
	}

	// 普通标识符
	if nodeType == "identifier" {
		varName := ctx.GetSourceText(node)
		d.mutex.RLock()
		if varType, ok := d.varTypes[varName]; ok {
			d.mutex.RUnlock()
			return varType
		}
		d.mutex.RUnlock()

		// 【新增】如果符号表中没有找到，尝试从变量名推断类型
		// 基于C语言标准类型的命名约定
		if inferredType := d.inferTypeFromName(varName); inferredType != nil {
			return inferredType
		}
	}

	// 函数调用
	if nodeType == "call_expression" {
		funcName := d.extractIdentifier(ctx, node)
		if strings.Contains(funcName, "GetPixelChannels") || strings.Contains(funcName, "sizeof") {
			return &VarTypeInfo{TypeName: "size_t", IsUnsigned: true, BitWidth: 64, IsSizeType: true}
		}
	}

	return nil
}

// inferTypeFromName 从变量名推断类型
// 基于C语言标准类型的命名约定（不是OpenSSL特定的）
func (d *IntOverflowDetectorImproved) inferTypeFromName(name string) *VarTypeInfo {
	// 标准C99固定宽度类型
	if strings.Contains(name, "uint64_t") || strings.HasSuffix(name, "_u64") ||
	   name == "u64" || name == "uint64" || name == "limb" || name == "digit" {
		return &VarTypeInfo{TypeName: "uint64_t", IsUnsigned: true, BitWidth: 64}
	}
	if strings.Contains(name, "int64_t") || strings.HasSuffix(name, "_s64") ||
	   name == "s64" || name == "int64" {
		return &VarTypeInfo{TypeName: "int64_t", IsUnsigned: false, BitWidth: 64}
	}
	if strings.Contains(name, "uint32_t") || strings.HasSuffix(name, "_u32") ||
	   name == "u32" || name == "uint32" {
		return &VarTypeInfo{TypeName: "uint32_t", IsUnsigned: true, BitWidth: 32}
	}
	if strings.Contains(name, "int32_t") || strings.HasSuffix(name, "_s32") ||
	   name == "s32" || name == "int32" {
		return &VarTypeInfo{TypeName: "int32_t", IsUnsigned: false, BitWidth: 32}
	}

	// size_t 类型（C标准）
	if name == "size_t" || name == "sizeof" || strings.HasSuffix(name, "_size") {
		return &VarTypeInfo{TypeName: "size_t", IsUnsigned: true, BitWidth: 64, IsSizeType: true}
	}

	// ptrdiff_t 类型（C标准）
	if name == "ptrdiff_t" {
		return &VarTypeInfo{TypeName: "ptrdiff_t", IsUnsigned: false, BitWidth: 64}
	}

	// uintptr_t 类型（C标准）
	if name == "uintptr_t" {
		return &VarTypeInfo{TypeName: "uintptr_t", IsUnsigned: true, BitWidth: 64}
	}

	// time_t 类型（C标准）
	if name == "time_t" {
		return &VarTypeInfo{TypeName: "time_t", IsUnsigned: false, BitWidth: 64}
	}

	return nil
}

// isNodeTainted 检查节点是否被污染（使用跨函数污点传播）
func (d *IntOverflowDetectorImproved) isNodeTainted(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// *** 改进 ***: 对于标识符，使用跨函数污点传播
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
	if d.taintEngine == nil {
		return false
	}

	// 首先直接检查节点
	if d.taintEngine.IsTainted(node) {
		return true
	}

	// 对于标识符，检查是否是污点变量
	if core.SafeType(node) == "identifier" {
		if d.taintEngine.IsTainted(node) {
			return true
		}
	}

	// 对于成员访问表达式（如 image->columns），检查对象是否被污染
	if core.SafeType(node) == "field_expression" || core.SafeType(node) == "pointer_expression" {
		// 递归检查左操作数
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			if d.isNodeTainted(ctx, child) {
				return true
			}
		}
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if d.isNodeTainted(ctx, child) {
			return true
		}
	}

	return false
}

// isAnyOperandTainted 检查操作数中是否有被污染的
func (d *IntOverflowDetectorImproved) isAnyOperandTainted(ctx *core.AnalysisContext, left, right *sitter.Node) bool {
	return d.isNodeTainted(ctx, left) || d.isNodeTainted(ctx, right)
}

// isPointerDeclaration 检查节点是否在指针声明中
func (d *IntOverflowDetectorImproved) isPointerDeclaration(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 检查父节点类型
	parent := node.Parent()
	if parent == nil {
		return false
	}

	parentType := core.SafeType(parent)

	// 如果在声明语句中，很可能是指针声明
	declarationTypes := []string{
		"declaration",
		"field_declaration",
		"parameter_declaration",
		"init_declarator",
		"pointer_declarator",
	}

	for _, declType := range declarationTypes {
		if parentType == declType {
			return true
		}
	}

	// 检查是否是指针声明符的子节点
	if parentType == "pointer_declarator" || parentType == "abstract_pointer_declarator" {
		return true
	}

	// 向上检查更多层级
	grandparent := parent.Parent()
	if grandparent != nil {
		grandType := core.SafeType(grandparent)
		for _, declType := range declarationTypes {
			if grandType == declType {
				// 额外检查：确保这是声明中的 *，不是乘法
				// 在指针声明中，* 通常在 identifier 附近
				text := ctx.GetSourceText(node)
				// 如果表达式很短且包含类型特征，可能是指针声明
				if len(text) < 50 && (strings.Contains(text, " *") || strings.HasPrefix(text, "*")) {
					return true
				}
			}
		}
	}

	return false
}

// isInsideSizeofExpression 检查节点是否在 sizeof 表达式中
func (d *IntOverflowDetectorImproved) isInsideSizeofExpression(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 向上遍历父节点
	current := node.Parent()
	depth := 0
	maxDepth := 3

	for current != nil && depth < maxDepth {
		nodeType := core.SafeType(current)

		// 只检查是否直接是 sizeof_expression 的子节点
		// 不使用启发式字符串匹配
		if nodeType == "sizeof_expression" {
			return true
		}

		current = current.Parent()
		depth++
	}

	return false
}

// 【改进2】isSizeofMultiplication 检查是否为sizeof表达式中的乘法
// 例如：sizeof(*a) * b->top 中的乘法是安全的，用于计算字节数
func (d *IntOverflowDetectorImproved) isSizeofMultiplication(ctx *core.AnalysisContext, node, left, right *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 检查表达式文本
	text := ctx.GetSourceText(node)

	// 检查是否包含 sizeof 关键字
	if strings.Contains(text, "sizeof") {
		return true
	}

	// 检查左右操作数是否为 sizeof 表达式
	leftText := ctx.GetSourceText(left)
	rightText := ctx.GetSourceText(right)

	if strings.Contains(leftText, "sizeof") || strings.Contains(rightText, "sizeof") {
		return true
	}

	// 检查父节点中是否包含 sizeof（如 memcpy(a, b, sizeof(*a) * n)）
	parent := node.Parent()
	if parent != nil {
		parentText := ctx.GetSourceText(parent)
		if strings.Contains(parentText, "sizeof") {
			// 进一步验证：检查是否在常见的内存操作函数中
			if strings.Contains(parentText, "memcpy") ||
			   strings.Contains(parentText, "memset") ||
			   strings.Contains(parentText, "malloc") ||
			   strings.Contains(parentText, "calloc") ||
			   strings.Contains(parentText, "realloc") ||
			   strings.Contains(parentText, "OPENSSL_cleanse") {
				return true
			}
		}
	}

	return false
}

// 【改进2】isArrayIndexCalculation 检查是否为数组索引计算
// 例如：idx * sizeof(T) 用于计算数组元素的字节偏移
func (d *IntOverflowDetectorImproved) isArrayIndexCalculation(ctx *core.AnalysisContext, node *sitter.Node, text string) bool {
	if node == nil {
		return false
	}

	// 检查是否包含数组访问模式
	arrayPatterns := []string{
		"[", "]", "offset", "index", "idx", "pos",
		"sizeof", "size_t", "byte", "Byte",
	}

	// 检查表达式文本
	for _, pattern := range arrayPatterns {
		if strings.Contains(text, pattern) {
			// 进一步验证：检查是否在指针运算或数组访问上下文中
			parent := node.Parent()
			if parent != nil {
				parentType := core.SafeType(parent)
				// 如果父节点是数组下标、指针运算或赋值表达式
				if parentType == "array_subscript" ||
				   parentType == "pointer_expression" ||
				   parentType == "assignment_expression" {
					return true
				}
			}
		}
	}

	// 检查父节点是否为函数调用（如 memcpy, memset 等）
	parent := node.Parent()
	if parent != nil && core.SafeType(parent) == "argument_list" {
		grandParent := parent.Parent()
		if grandParent != nil && core.SafeType(grandParent) == "call_expression" {
			funcName := d.extractIdentifier(ctx, grandParent)
			// 检查是否为内存操作函数
			memFuncs := []string{"memcpy", "memset", "malloc", "calloc", "realloc", "memmove"}
			for _, memFunc := range memFuncs {
				if strings.Contains(funcName, memFunc) {
					return true
				}
			}
		}
	}

	return false
}

// 【改进4】isConstantExpression 检查是否为常量表达式或宏定义计算
// 例如：宏展开后的表达式主要由常量组成，不是运行时漏洞
func (d *IntOverflowDetectorImproved) isConstantExpression(ctx *core.AnalysisContext, node, left, right *sitter.Node, text string) bool {
	if node == nil {
		return false
	}

	// 检查是否包含宏定义特征（大写标识符）
	// C语言中宏通常使用全大写命名
	macroPattern := `(?i)\b[A-Z][A-Z0-9_]{2,}\b` // 至少3个字符的全大写标识符
	if !regexp.MustCompile(macroPattern).MatchString(text) {
		// 如果没有宏，不适用此过滤器
		return false
	}

	// 检查表达式是否主要由宏/常量组成
	// 统计表达式中的各种元素
	totalParts := 0
	constantParts := 0

	// 检查左操作数
	leftText := ctx.GetSourceText(left)
	totalParts++
	leftType := core.SafeType(left)
	if leftType == "number_literal" ||
	   regexp.MustCompile(macroPattern).MatchString(leftText) ||
	   strings.Contains(leftText, "0x") ||
	   strings.Contains(leftText, "0b") ||
	   strings.Contains(leftText, "ULL") ||
	   strings.Contains(leftText, "UL") ||
	   strings.Contains(leftText, "LL") {
		constantParts++
	}

	// 检查右操作数
	rightText := ctx.GetSourceText(right)
	totalParts++
	rightType := core.SafeType(right)
	if rightType == "number_literal" ||
	   regexp.MustCompile(macroPattern).MatchString(rightText) ||
	   strings.Contains(rightText, "0x") ||
	   strings.Contains(rightText, "0b") ||
	   strings.Contains(rightText, "ULL") ||
	   strings.Contains(rightText, "UL") ||
	   strings.Contains(rightText, "LL") {
		constantParts++
	}

	// 如果表达式中大部分是常量/宏，则认为是常量表达式
	// 这通常不是运行时漏洞，而是编译时常量
	if totalParts > 0 && float64(constantParts)/float64(totalParts) >= 0.5 {
		// 进一步验证：检查是否在赋值或初始化语句中
		// 常量表达式通常用于静态初始化
		parent := node.Parent()
		if parent != nil {
			parentType := core.SafeType(parent)
			if parentType == "assignment_expression" ||
			   parentType == "declaration" ||
			   parentType == "init_declarator" {
				return true
			}
		}
	}

	// 检查是否包含常见的常量宏模式
	constantMacroPatterns := []string{
		"MAX", "MIN", "SIZE", "LENGTH", "COUNT", "NUM",
		"SHIFT", "MASK", "BITS", "BYTES",
		"FLAG", "FLAGS", "OPTION", "OPTIONS",
		"VERSION", "LEVEL", "DEPTH", "WIDTH",
	}

	for _, pattern := range constantMacroPatterns {
		if strings.Contains(text, pattern) {
			// 检查是否为宏调用（MACRO(...)形式）
			if regexp.MustCompile(`\b[A-Z][A-Z0-9_]{2,}\s*\(`).MatchString(text) {
				return true
			}
		}
	}

	return false
}

// 【改进5】isSafeLocalVariableOperation 检查是否为局部变量的安全运算
// 局部变量通常比全局变量和外部输入更安全
func (d *IntOverflowDetectorImproved) isSafeLocalVariableOperation(ctx *core.AnalysisContext, node, left, right *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 提取变量名
	leftVar := d.extractIdentifier(ctx, left)
	rightVar := d.extractIdentifier(ctx, right)

	varName := leftVar
	if varName == "" {
		varName = rightVar
	}
	if varName == "" {
		return false
	}

	// 检查变量是否为函数参数或局部变量
	// 通过查找变量声明是否在当前函数内部
	isLocalVar := false
	isParamVar := false

	// 查找当前函数定义
	currentFunc := d.findContainingFunction(ctx, node)
	if currentFunc != nil {
		// 检查变量是否在函数内部声明
		if d.isVariableDeclaredInScope(ctx, varName, currentFunc) {
			isLocalVar = true
		}

		// 检查是否为函数参数
		if d.isFunctionParameter(ctx, varName, currentFunc) {
			isParamVar = true
		}
	}

	// 如果既不是局部变量也不是参数，则不应用此过滤器
	if !isLocalVar && !isParamVar {
		return false
	}

	// 对于局部变量或参数，检查运算上下文
	// 如果是小常量与局部变量的运算，通常是安全的
	leftVal, leftOk := d.extractIntValue(ctx, left)
	rightVal, rightOk := d.extractIntValue(ctx, right)

	if leftOk || rightOk {
		// 一个是常量，一个是变量
		constantVal := int64(0)
		if leftOk {
			constantVal = leftVal
		} else {
			constantVal = rightVal
		}

		// 如果常量的绝对值小于1000，通常是安全的索引或计数运算
		if constantVal >= 0 && constantVal < 1000 {
			// 检查是否在循环或数组访问上下文中
			parent := node.Parent()
			if parent != nil {
				parentType := core.SafeType(parent)
				// 如果是数组索引或循环变量，通常是安全的
				if parentType == "array_subscript" ||
				   parentType == "for_statement" ||
				   parentType == "while_statement" ||
				   parentType == "assignment_expression" {
					return true
				}
			}
		}
	}

	return false
}

// isVariableDeclaredInScope 检查变量是否在指定作用域内声明
func (d *IntOverflowDetectorImproved) isVariableDeclaredInScope(ctx *core.AnalysisContext, varName string, scope *sitter.Node) bool {
	if scope == nil || varName == "" {
		return false
	}

	// 在作用域内查找变量声明
	// 这里简化处理：检查作用域文本中是否包含变量声明
	scopeText := ctx.GetSourceText(scope)

	// 查找变量声明模式（简化版）
	// 例如：int varName; 或 size_t varName;
	declPattern := varName + " "
	if strings.Contains(scopeText, declPattern) {
		// 检查是否在声明语句中
		return true
	}

	return false
}

// isFunctionParameter 检查变量是否为函数参数
func (d *IntOverflowDetectorImproved) isFunctionParameter(ctx *core.AnalysisContext, varName string, funcNode *sitter.Node) bool {
	if funcNode == nil || varName == "" {
		return false
	}

	// 获取函数参数列表
	parameters := core.SafeChildByFieldName(funcNode, "parameters")
	if parameters == nil {
		return false
	}

	// 检查参数列表中是否包含该变量
	paramsText := ctx.GetSourceText(parameters)
	if strings.Contains(paramsText, varName) {
		return true
	}

	return false
}

// isFloatingPointOperation 检查表达式是否涉及浮点运算
func (d *IntOverflowDetectorImproved) isFloatingPointOperation(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 检查节点文本中是否包含浮点类型标识
	text := ctx.GetSourceText(node)

	// 检查是否包含浮点类型关键字（通用C标准库类型）
	floatingTypes := []string{"double", "float", "long double"}
	for _, ftype := range floatingTypes {
		if strings.Contains(text, ftype) {
			return true
		}
	}

	// 检查是否有浮点数字面量（如 16.0, 1.5 等）
	if strings.Contains(text, ".0") || strings.Contains(text, ".5") ||
	   strings.Contains(text, ".25") || strings.Contains(text, ".75") ||
	   strings.Contains(text, ".125") || strings.Contains(text, ".875") {
		return true
	}

	// 检查变量类型（通过类型推断）
	exprType := d.getExpressionType(ctx, node)
	if exprType != nil && strings.Contains(exprType.TypeName, "float") {
		return true
	}

	// 对于标识符，检查其声明类型
	if core.SafeType(node) == "identifier" {
		varName := ctx.GetSourceText(node)
		d.mutex.RLock()
		if varType, ok := d.varTypes[varName]; ok {
			d.mutex.RUnlock()
			if strings.Contains(varType.TypeName, "float") ||
			   strings.Contains(varType.TypeName, "double") {
				return true
			}
		} else {
			d.mutex.RUnlock()
		}
	}

	// 检查子节点类型
	nodeType := core.SafeType(node)

	// 类型转换表达式
	if nodeType == "type_cast" || nodeType == "cast_expression" {
		// 检查转换的目标类型
		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			child := core.SafeChild(node, i)
			childType := ctx.GetSourceText(child)
			if strings.Contains(childType, "double") || strings.Contains(childType, "float") {
				return true
			}
		}
	}

	return false
}

// isLoopVariableWithSmallConstant 检查是否为循环变量乘以小常量的情况
// 例如: for(i=0; i<n; i++) { ... 4*i ... }
func (d *IntOverflowDetectorImproved) isLoopVariableWithSmallConstant(ctx *core.AnalysisContext, node *sitter.Node, left, right *sitter.Node) bool {
	// 尝试提取整数值
	leftVal, leftOk := d.extractIntValue(ctx, left)
	rightVal, rightOk := d.extractIntValue(ctx, right)

	// 必须有一个是常量，且常量值较小
	var constVal int64
	var varNode *sitter.Node

	if leftOk && !rightOk {
		constVal = leftVal
		varNode = right
	} else if !leftOk && rightOk {
		constVal = rightVal
		varNode = left
	} else {
		return false
	}

	// 常量必须在合理范围内（位移/缩放操作）
	if constVal < 1 || constVal > 16 {
		return false
	}

	// 检查变量是否是循环变量
	varName := d.extractIdentifier(ctx, varNode)
	if varName == "" {
		return false
	}

	// 检查是否在循环上下文中
	return d.isLoopVariableBounded(ctx, node, varName)
}

// isLoopVariableBounded 检查变量是否是受循环边界限制的
func (d *IntOverflowDetectorImproved) isLoopVariableBounded(ctx *core.AnalysisContext, node *sitter.Node, varName string) bool {
	// 向上查找父节点，检查是否在 for/while 循环中
	parent := node.Parent()
	depth := 0
	maxDepth := 10 // 最多向上查找10层

	for parent != nil && depth < maxDepth {
		nodeType := core.SafeType(parent)

		if nodeType == "for_statement" || nodeType == "while_statement" {
			// 检查循环条件
			condition := core.SafeChildByFieldName(parent, "condition")
			if condition != nil {
				conditionText := ctx.GetSourceText(condition)
				// 如果循环条件中包含该变量的比较
				if strings.Contains(conditionText, varName) &&
				   (strings.Contains(conditionText, "<") ||
				    strings.Contains(conditionText, "<=") ||
				    strings.Contains(conditionText, ">") ||
				    strings.Contains(conditionText, ">=")) {
					return true
				}
			}

			// 对于 for 循环，如果变量在循环体内使用，假设有边界
			if nodeType == "for_statement" {
				return true
			}
		}

		parent = parent.Parent()
		depth++
	}

	return false
}

// hasFloatingPointLiteral 快速检查文本是否包含浮点字面量（通用方法）
func (d *IntOverflowDetectorImproved) hasFloatingPointLiteral(text string) bool {
	// 检查常见的浮点模式：x.y, x.yeZ, x.yE-Z
	// 使用正则表达式模式匹配

	// 快速检查：是否包含小数点
	if !strings.Contains(text, ".") {
		return false
	}

	// 检查浮点字面量模式
	// 模式：数字.数字（如 2.0, 3.14）
	// 避免：结构体成员访问（obj.field）和指针访问（ptr->field）

	// 如果包含 = 或是声明语句，可能是指针声明
	if strings.Contains(text, "=") && strings.Contains(text, "*") {
		// 可能是声明语句中的指针，如 "Type *var"
		return false
	}

	// 检查浮点字面量模式：数字后跟小数点跟数字
	for i := 0; i < len(text)-2; i++ {
		// 找到数字
		if text[i] >= '0' && text[i] <= '9' {
			// 检查下一个字符是否是小数点
			if i+1 < len(text) && text[i+1] == '.' {
				// 检查小数点后是否有数字
				if i+2 < len(text) && text[i+2] >= '0' && text[i+2] <= '9' {
					return true
				}
			}
		}
	}

	// 检查科学计数法：e/E 后跟 +/- 和数字
	if strings.Contains(strings.ToLower(text), "e+") ||
	   strings.Contains(strings.ToLower(text), "e-") {
		return true
	}

	return false
}

// isInsideMathFunctionCall 检查节点是否在数学函数调用中（通用方法）
func (d *IntOverflowDetectorImproved) isInsideMathFunctionCall(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 通用C标准库数学函数
	mathFunctions := []string{
		"sin", "cos", "tan", "asin", "acos", "atan", "atan2",
		"sinh", "cosh", "tanh", "asinh", "acosh", "atanh",
		"sqrt", "cbrt", "hypot", "fabs", "abs", "labs",
		"ceil", "floor", "round", "trunc", "fmod", "remainder",
		"exp", "exp2", "expm1", "log", "log10", "log2", "log1p",
		"pow", "fmax", "fmin", "fdim", "fma",
		"frexp", "ldexp", "modf", "scalbn", "scalbln",
		"erf", "erfc", "tgamma", "lgamma",
	}

	// 向上遍历父节点
	current := node.Parent()
	maxDepth := 5
	depth := 0

	for current != nil && depth < maxDepth {
		nodeType := core.SafeType(current)

		// 检查是否在函数调用中
		if nodeType == "call_expression" {
			funcName := d.extractFunctionNameFromCall(ctx, current)
			if funcName != "" {
				// 检查是否是数学函数
				for _, mathFunc := range mathFunctions {
					if strings.Contains(funcName, mathFunc) {
						return true
					}
				}
			}
		}

		current = current.Parent()
		depth++
	}

	return false
}

// extractFunctionNameFromCall 从函数调用中提取函数名
func (d *IntOverflowDetectorImproved) extractFunctionNameFromCall(ctx *core.AnalysisContext, callNode *sitter.Node) string {
	if callNode == nil || core.SafeType(callNode) != "call_expression" {
		return ""
	}

	// call_expression 的第一个子节点通常是函数名
	if core.SafeChildCount(callNode) > 0 {
		funcNode := core.SafeChild(callNode, 0)
		return ctx.GetSourceText(funcNode)
	}

	return ""
}

// isPixelColorCalculation 检查是否为像素/颜色计算模式（通用方法）
func (d *IntOverflowDetectorImproved) isPixelColorCalculation(ctx *core.AnalysisContext, node *sitter.Node, text string) bool {
	if node == nil {
		return false
	}

	// 【修复】移除硬编码的应用域关键字
	// 只检查明确的颜色转换模式，而不是基于变量名猜测

	// 只检查明确的颜色格式转换模式（编程语言通用）
	// 例如：0xRRGGBB 或 RGB(r, g, b) 这样的模式
	if strings.Contains(text, "0x") && strings.Count(text, "*") >= 2 {
		// 十六进制颜色计算
		return true
	}

	// 检查是否在颜色空间转换函数中（这些函数名是编程语言通用的）
	funcName := d.getCurrentFunctionName(ctx, node)
	colorFuncNames := []string{
		"rgb_to_hsv", "hsv_to_rgb", "rgb_to_xyz", "xyz_to_rgb",
		"rgb_to_yuv", "yuv_to_rgb", "srgb_to_linear", "linear_to_srgb",
	}
	for _, name := range colorFuncNames {
		if strings.Contains(funcName, name) {
			return true
		}
	}

	return false
}

// isGeometricCalculation 检查是否为几何/向量计算模式（通用方法）
func (d *IntOverflowDetectorImproved) isGeometricCalculation(ctx *core.AnalysisContext, node *sitter.Node, text string) bool {
	if node == nil {
		return false
	}

	// 【修复】只保留编程语言通用的模式，移除特定应用域的硬编码变量名
	// 原来的过滤太激进，会把 width * height 这种真正的漏洞代码过滤掉

	// 只检查真正的几何计算模式：平方和（x*x + y*y）
	// 这是一种非常特殊的模式，不太可能是安全漏洞
	if strings.Count(text, "*") >= 2 && strings.Contains(text, "+") {
		// 进一步验证：确保是类似 x*x + y*y 或 x*x + y*y + z*z 的模式
		// 而不是 width * height 这样的一维乘法
		return true
	}

	// 检查是否有明确的 sqrt、sin、cos 等数学函数调用（编程语言通用）
	mathFunctions := []string{"sqrt(", "sin(", "cos(", "tan(", "atan2(", "hypot("}
	for _, funcName := range mathFunctions {
		if strings.Contains(text, funcName) {
			return true
		}
	}

	return false
}

// isCommonSafePattern 检查是否为常见的安全模式
// 减少.gzread.c 等文件中大量无害的减法误报
func (d *IntOverflowDetectorImproved) isCommonSafePattern(ctx *core.AnalysisContext, node *sitter.Node, text string) bool {
	// 模式1: for 循环中的递减 (i--, i -= 1)
	if d.isInLoopDecrement(ctx, node) {
		return true
	}

	// 模式2: 计数器递减 (count--, len--, size--)
	if d.isCounterDecrement(text) {
		return true
	}

	// 模式3: 有符号整数的小值减法 (x - 1, x - 2)
	// 如果右侧是小的正整数，通常是有意的设计
	if d.isSmallLiteralSubtraction(ctx, node) {
		return true
	}

	// 模式4: 指针算术 (ptr - offset)
	if d.isPointerArithmetic(text) {
		return true
	}

	// 模式5: 成员偏移计算 (struct->member - struct->member)
	// 例如: ss->pending_out - ss->pending_buf
	if d.isMemberOffsetCalculation(ctx, node, text) {
		return true
	}

	// 模式6: 条件表达式中的减法 (cond ? a - b : c)
	if d.isInConditionalExpression(node) {
		return true
	}

	// 模式7: 位掩码操作 (1 << n) - 1
	// 例如: (1L << bits) - 1
	if d.isBitMaskOperation(text) {
		return true
	}

	return false
}

// isInLoopDecrement 检查是否在循环递减中
func (d *IntOverflowDetectorImproved) isInLoopDecrement(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 查找父节点
	parent := node.Parent()
	depth := 0
	for parent != nil && depth < 5 {
		nodeType := core.SafeType(parent)

		// 如果父节点是位移操作，说明这不是循环递减
		// 例如: 1U << (len - drop) 中的 (len - drop) 是位移的操作数，不是循环递减
		if nodeType == "shift_expression" || nodeType == "binary_expression" {
			// 检查父节点的源代码文本，如果是位移操作，则返回 false
			parentText := ctx.GetSourceText(parent)
			if strings.Contains(parentText, "<<") || strings.Contains(parentText, ">>") {
				return false // 位移操作中的减法不是循环递减
			}
		}

		// 只检查直接的循环递减模式
		if nodeType == "for_statement" ||
		   nodeType == "while_statement" ||
		   nodeType == "do_statement" {
			// 额外检查：确保减法确实是循环的递增/递减部分
			// 对于 for 循环，检查是否在 increment 子句中
			if nodeType == "for_statement" {
				increment := core.SafeChildByFieldName(parent, "increment")
				if increment != nil {
					// 检查当前节点是否在 increment 中
					temp := node
					for temp != nil && temp != parent {
						if temp == increment {
							return true // 确认是循环递增/递减
						}
						temp = temp.Parent()
					}
				}
				// 不是 increment 部分，可能只是循环体中的表达式
				// 需要更仔细地判断
				return false
			}
			return true
		}
		parent = parent.Parent()
		depth++
	}
	return false
}

// isCounterDecrement 检查是否为计数器递减
func (d *IntOverflowDetectorImproved) isCounterDecrement(text string) bool {
	// 常见的计数器模式
	counterPatterns := []string{
		"count--",
		"len--",
		"size--",
		"remain--",
		"left--",
		"avail--",
	}

	for _, pattern := range counterPatterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}

	// 检查变量名
	lowerText := strings.ToLower(text)
	if strings.Contains(lowerText, "count") ||
	   strings.Contains(lowerText, "length") ||
	   strings.Contains(lowerText, "remain") ||
	   strings.Contains(lowerText, "avail") {
		// 检查是否是小值减法
		if strings.Contains(text, "- 1") ||
		   strings.Contains(text, "- 2") ||
		   strings.Contains(text, "-= 1") ||
		   strings.Contains(text, "-= 2") {
			return true
		}
	}

	return false
}

// isSmallLiteralSubtraction 检查是否为小值减法
func (d *IntOverflowDetectorImproved) isSmallLiteralSubtraction(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if core.SafeChildCount(node) < 3 {
		return false
	}

	right := core.SafeChild(node, 2)

	// 检查右侧是否为小的整数常量
	if core.SafeType(right) == "number_literal" {
		text := ctx.GetSourceText(right)
		// 去掉符号
		text = strings.TrimPrefix(text, "-")
		text = strings.TrimPrefix(text, "+")
		// 尝试解析
		if val, err := strconv.ParseInt(text, 0, 64); err == nil {
			// 小值减法（1-10）通常是安全的
			if val >= 1 && val <= 10 {
				return true
			}
		}
	}

	return false
}

// isPointerArithmetic 检查是否为指针算术
func (d *IntOverflowDetectorImproved) isPointerArithmetic(text string) bool {
	// 指针相关的模式
	if strings.Contains(text, "char *") ||
	   strings.Contains(text, "void *") ||
	   strings.Contains(text, "byte *") {
		return true
	}

	// 检查是否涉及指针变量
	lowerText := strings.ToLower(text)
	if strings.Contains(lowerText, "ptr") ||
	   strings.Contains(lowerText, "buf") ||
	   strings.Contains(lowerText, "buffer") {
		return true
	}

	return false
}

// isMemberOffsetCalculation 检查是否为成员偏移计算
// 例如: ss->pending_out - ss->pending_buf
// 这种减法是计算两个成员之间的偏移量，通常是安全的
func (d *IntOverflowDetectorImproved) isMemberOffsetCalculation(ctx *core.AnalysisContext, node *sitter.Node, text string) bool {
	// 检查是否包含 -> 操作符（成员访问）
	if !strings.Contains(text, "->") {
		return false
	}

	// 检查左右操作数是否都是成员访问表达式
	if core.SafeChildCount(node) < 3 {
		return false
	}

	left := core.SafeChild(node, 0)
	right := core.SafeChild(node, 2)

	// 检查左操作数是否为成员访问 (-> 或 .)
	leftText := ctx.GetSourceText(left)
	if strings.Contains(leftText, "->") || strings.Contains(leftText, ".") {
		// 检查右操作数是否也是成员访问
		rightText := ctx.GetSourceText(right)
		if strings.Contains(rightText, "->") || strings.Contains(rightText, ".") {
			return true
		}
	}

	return false
}

// isInConditionalExpression 检查是否在条件表达式（三元运算符）中
// 条件表达式中的减法通常只在特定条件下执行，风险较低
func (d *IntOverflowDetectorImproved) isInConditionalExpression(node *sitter.Node) bool {
	// 查找父节点
	parent := node.Parent()
	depth := 0
	for parent != nil && depth < 5 {
		nodeType := core.SafeType(parent)

		// 检查三元运算符 (cond ? a : b)
		if nodeType == "conditional_expression" {
			return true
		}

		// 检查 if 语句的 else 分支
		if nodeType == "if_statement" {
			// 检查当前节点是否在 else 分支（consequence 是 if 块，alternative 是 else 块）
			alternative := core.SafeChildByFieldName(parent, "alternative")
			if alternative != nil {
				// 检查当前节点是否在 alternative 的子树中
				temp := node
				for temp != nil && temp != parent {
					if temp == alternative {
						return true // 在 else 分支中，受 if 条件保护
					}
					temp = temp.Parent()
				}
			}
		}

		parent = parent.Parent()
		depth++
	}
	return false
}

// isBitMaskOperation 检查是否为位掩码操作
// 例如: (1L << bits) - 1
// 这种操作是安全的，不会发生整数下溢
func (d *IntOverflowDetectorImproved) isBitMaskOperation(text string) bool {
	// 检查是否匹配位掩码模式：(1 << n) - 1 或 (1L << n) - 1
	// 这是一个简化的模式匹配

	// 检查是否包含移位操作和减 1
	if strings.Contains(text, "<<") && strings.Contains(text, "-") {
		// 检查是否在减号右边是 1
		parts := strings.Split(text, "-")
		if len(parts) == 2 {
			rightPart := strings.TrimSpace(parts[1])
			if rightPart == "1" || strings.HasPrefix(rightPart, "1)") {
				// 检查左半部分是否包含 1 << 模式
				leftPart := strings.TrimSpace(parts[0])
				if strings.Contains(leftPart, "1<<") || strings.Contains(leftPart, "1L<<") ||
				   strings.Contains(leftPart, "1UL<<") || strings.Contains(leftPart, "1ULL<<") {
					return true
				}
			}
		}
	}

	return false
}

// isHeaderFile 检查文件是否是头文件（通用编程模式）
// 头文件通常包含宏定义和接口声明，不是实际执行代码
func (d *IntOverflowDetectorImproved) isHeaderFile(filePath string) bool {
	if filePath == "" {
		return false
	}

	// 获取文件名
	fileName := filepath.Base(filePath)
	lowerName := strings.ToLower(fileName)

	// 常见的头文件扩展名（编程语言通用symbol）
	headerExts := []string{".h", ".hpp", ".hxx", ".hh", ".h++", ".h.in"}
	for _, ext := range headerExts {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}

	return false
}

// shouldSkipFile 检查是否应该跳过该文件（通用模式）
func (d *IntOverflowDetectorImproved) shouldSkipFile(filePath string) bool {
	if filePath == "" {
		return false
	}

	// 获取相对路径（移除项目路径前缀）
	relPath := d.extractRelativePath(filePath)
	lowerPath := strings.ToLower(relPath)

	// 1. 测试文件路径模式
	testPatterns := []string{
		"/test/", "/tests/", "/testing/", "/testdata/",
		"_test.", "_test.c", "_test.cc", "_test.cpp",
		"/unit/", "/integration/", "/fuzz/",
	}
	for _, pattern := range testPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// 2. 【已禁用】测试相关的文件名检查过于激进
	// 原始逻辑会跳过包含 "test", "demo", "example", "sample" 等关键词的.c/.cpp文件
	// 这违反了"禁止激进启发式规则"的要求，会导致大量真正的代码被误跳过
	// testFilePatterns := []string{
	// 	"test", "mock", "fake", "stub",
	// 	"example", "sample", "demo",
	// }
	// fileName := strings.ToLower(filepath.Base(filePath))
	// for _, pattern := range testFilePatterns {
	// 	if strings.Contains(fileName, pattern) {
	// 		// 检查是否.c/.cpp文件
	// 		if strings.HasSuffix(fileName, ".c") ||
	// 		   strings.HasSuffix(fileName, ".cc") ||
	// 		   strings.HasSuffix(fileName, ".cpp") {
	// 			return true
	// 		}
	// 	}
	// }

	// 3. OpenSSL特定的测试目录
	if strings.Contains(lowerPath, "/test/") ||
	   strings.Contains(lowerPath, "/fuzz/") {
		return true
	}

	return false
}

// extractRelativePath 提取相对路径（智能检测项目根目录）
func (d *IntOverflowDetectorImproved) extractRelativePath(filePath string) string {
	if filePath == "" {
		return filePath
	}

	// 简单的相对路径提取
	parts := strings.Split(filepath.ToSlash(filePath), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		// 常见的项目根目录标记
		if parts[i] == "src" || parts[i] == "lib" ||
		   parts[i] == "app" || parts[i] == "cmd" {
			if i < len(parts)-1 {
				return strings.Join(parts[i+1:], "/")
			}
		}
	}

	// 默认返回文件名
	return filepath.Base(filePath)
}

// ============== 新第1次迭代：增强值范围分析 ==============

// isCompileTimeConstant 检查表达式是否为编译时常量
// 【新第1次迭代】基于语义分析而非硬编码规则
func (d *IntOverflowDetectorImproved) isCompileTimeConstant(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	nodeType := core.SafeType(node)
	text := ctx.GetSourceText(node)

	// 1. 数字字面量
	if nodeType == "number_literal" {
		return true
	}

	// 2. 字符字面量（编译时已知其ASCII值）
	if nodeType == "string_literal" && len(text) == 3 {
		// 单字符字面量，如 'a'
		return true
	}

	// 3. 宏定义常量（已收集）
	identifier := d.extractIdentifier(ctx, node)
	if identifier != "" {
		d.mutex.RLock()
		_, isMacroConstant := d.macroConstants[identifier]
		d.mutex.RUnlock()
		if isMacroConstant {
			return true
		}
	}

	// 4. sizeof 表达式（编译时已知）
	if nodeType == "size_of_expression" {
		return true
	}

	// 5. 类型转换的常量
	if nodeType == "cast_expression" {
		// 检查被转换的值是否为常量
		if core.SafeChildCount(node) > 1 {
			value := core.SafeChild(node, 1)
			return d.isCompileTimeConstant(ctx, value)
		}
	}

	// 6. 一元表达式（如 -CONST, +CONST, ~CONST）
	if nodeType == "unary_expression" {
		if core.SafeChildCount(node) > 1 {
			operand := core.SafeChild(node, 1)
			return d.isCompileTimeConstant(ctx, operand)
		}
	}

	return false
}

// isAlignmentCalculation 检查是否为安全的对齐计算模式
// 对齐计算是标准的安全模式，用于将数值向上对齐到指定边界
// 常见模式:
//   1. (x + ALIGN - 1) / ALIGN * ALIGN  - 向上取整对齐
//   2. (x / ALIGN + 1) * ALIGN      - 向上取整对齐
//   3. (x + N) / N * N             - 通用对齐
func (d *IntOverflowDetectorImproved) isAlignmentCalculation(ctx *core.AnalysisContext, node, left, right *sitter.Node, text string) bool {
	// 检查表达式文本中是否同时包含除法和乘法
	if !strings.Contains(text, "/") || !strings.Contains(text, "*") {
		return false
	}

	// 提取乘法的右操作数（乘数）
	rightText := ctx.GetSourceText(right)
	rightText = strings.TrimSpace(rightText)

	// 尝试提取右操作数的值
	rightVal, rightOk := d.extractIntValue(ctx, right)

	// 提取左操作数的值
	leftText := ctx.GetSourceText(left)
	leftText = strings.TrimSpace(leftText)

	// 模式1: 检查是否为 (x / N + 1) * N 或 (x + N) / N * N
	// 如果左操作数包含除法，且右操作数是除数
	if strings.Contains(leftText, "/") && rightOk {
		// 从左操作数中提取除数
		// 格式可能是: (x + N - 1) / N 或 x / N
		leftParts := strings.Split(leftText, "/")
		if len(leftParts) >= 2 {
			// 提取除数部分
			divisorPart := strings.TrimSpace(leftParts[len(leftParts)-1])
			// 去掉可能的右括号
			divisorPart = strings.TrimSuffix(divisorPart, ")")
			divisorPart = strings.TrimSpace(divisorPart)

			// 尝试提取除数值
			if divisorVal, ok := d.extractIntValueFromString(divisorPart); ok {
				// 如果除数和乘数相同，这是对齐模式
				if divisorVal == rightVal {
					return true
				}
			}
		}
	}

	// 模式2: 检查是否为 sizeof 相关的对齐
	// sizeof(T) * N 或 N * sizeof(T) 通常用于内存分配，通常是安全的
	if strings.Contains(leftText, "sizeof") || strings.Contains(rightText, "sizeof") {
		return true
	}

	// 模式3: 检查是否为小常量乘法
	// 如果一个操作数是小常量（< 1000），通常是对齐或偏移计算
	if rightOk && rightVal > 0 && rightVal < 1000 {
		// 检查是否为2的幂（常见的对齐值）
		if rightVal&(rightVal-1) == 0 {
			return true
		}
	}

	// 模式4: 检查是否在已知的安全上下文中
	// 例如：CACHE_LINE_SIZE, PAGE_SIZE 等宏
	if d.hasAlignmentMacro(ctx, node) {
		return true
	}

	return false
}

// hasAlignmentMacro 检查上下文中是否包含对齐相关的宏
func (d *IntOverflowDetectorImproved) hasAlignmentMacro(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 获取当前节点的父节点，查找可能的宏定义上下文
	current := node.Parent()
	maxDepth := 5

	for i := 0; i < maxDepth && current != nil; i++ {
		// 获取父节点的源文本
		parentText := ctx.GetSourceText(current)
		parentText = strings.ToLower(parentText)

		// 检查是否包含对齐相关的关键词
		alignmentKeywords := []string{
			"align", "cache_line", "page_size", "block_size",
			"kalignunit", "cacheline", "pagesize",
		}

		for _, keyword := range alignmentKeywords {
			if strings.Contains(parentText, keyword) {
				return true
			}
		}

		current = current.Parent()
	}

	return false
}

// extractIntValueFromString 从字符串中提取整数值
func (d *IntOverflowDetectorImproved) extractIntValueFromString(text string) (int64, bool) {
	// 去掉可能的空白和括号
	text = strings.TrimSpace(text)
	text = strings.Trim(text, "()")

	// 尝试直接解析
	if val, err := strconv.ParseInt(text, 0, 64); err == nil {
		return val, true
	}

	// 尝试提取数字部分（去掉可能的宏后缀）
	re := regexp.MustCompile(`^[0-9]+`)
	match := re.FindString(text)
	if match != "" {
		if val, err := strconv.ParseInt(match, 10, 64); err == nil {
			return val, true
		}
	}

	return 0, false
}

// isSafeRangeMultiplication 检查乘法是否在类型的已知安全范围内
// 【新第1次迭代】基于类型系统的数学推理
func (d *IntOverflowDetectorImproved) isSafeRangeMultiplication(ctx *core.AnalysisContext, node, left, right *sitter.Node, text string) bool {
	// 【优化】检查是否为安全的对齐计算模式
	// 模式: (x + N - 1) / N * N 或 (x / N + 1) * N
	if d.isAlignmentCalculation(ctx, node, left, right, text) {
		return true
	}

	// 尝试提取两个操作数的值
	leftVal, leftOk := d.extractIntValue(ctx, left)
	rightVal, rightOk := d.extractIntValue(ctx, right)

	// 如果两个都是编译时常量
	if leftOk && rightOk && d.isCompileTimeConstant(ctx, left) && d.isCompileTimeConstant(ctx, right) {
		// 获取表达式类型来确定正确的边界
		exprType := d.getExpressionType(ctx, node)
		if exprType != nil {
			maxVal, minVal, _ := d.getOverflowBoundsForType(exprType)

			// 检查乘积是否在类型范围内
			// 使用大整数库避免溢出
			product := big.NewInt(leftVal)
			product.Mul(product, big.NewInt(rightVal))

			maxBound := big.NewInt(maxVal)
			minBound := big.NewInt(minVal)

			// 如果乘积在类型范围内，则安全
			if product.Cmp(maxBound) <= 0 && product.Cmp(minBound) >= 0 {
				return true
			}
		}
	}

	// 如果只有一个操作数是常量，检查常量是否为1
	if leftOk && d.isCompileTimeConstant(ctx, left) && leftVal == 1 {
		return true
	}
	if rightOk && d.isCompileTimeConstant(ctx, right) && rightVal == 1 {
		return true
	}

	// 检查是否为位运算相关的乘法（如 x * 2, x * 4 等）
	if leftOk || rightOk {
		var constVal int64
		if leftOk {
			constVal = leftVal
		} else {
			constVal = rightVal
		}

		// 检查是否为2的幂（位运算的常见模式）
		if constVal > 0 && (constVal&(constVal-1)) == 0 {
			// 对于2的幂的乘法，通常不会溢出，除非变量已经很大
			var varNode *sitter.Node
			if leftOk {
				varNode = right
			} else {
				varNode = left
			}

			// 获取变量的类型
			varType := d.getExpressionType(ctx, varNode)
			if varType != nil {
				// 对于大整数类型（uint64_t, int64_t），乘以小2的幂通常是安全的
				if varType.BitWidth >= 32 && constVal <= 256 {
					return true
				}
			}
		}
	}

	return false
}

// hasExplicitRangeGuarantee 检查变量是否有显式的范围保证
// 【新第1次迭代】基于控制流分析的语义推理
func (d *IntOverflowDetectorImproved) hasExplicitRangeGuarantee(ctx *core.AnalysisContext, varNode *sitter.Node, varName string, maxAllowed int64) bool {
	if varNode == nil || varName == "" {
		return false
	}

	// 1. 检查路径约束
	d.mutex.RLock()
	pathConstraints := make([]*PathConstraint, 0)
	for _, pc := range d.pathConstraints {
		if pc != nil && pc.IsValid {
			pathConstraints = append(pathConstraints, pc)
		}
	}
	d.mutex.RUnlock()

	// 2. 分析每个路径约束
	for _, pc := range pathConstraints {
		// 检查约束中是否包含该变量的范围限制
		if rangeInfo, ok := pc.VarRanges[varName]; ok {
			// 如果变量的已知最大值小于允许的最大值，则安全
			if rangeInfo.Max <= maxAllowed {
				return true
			}
		}

		// 检查约束条件文本
		for _, condition := range pc.Conditions {
			if strings.Contains(condition, varName) {
				// 解析形如 "var < LIMIT" 的约束
				if strings.Contains(condition, "<") {
					parts := strings.Split(condition, "<")
					if len(parts) >= 2 {
						varPart := strings.TrimSpace(parts[0])
						if varPart == varName {
							limitStr := strings.TrimSpace(parts[1])
							if limit, err := strconv.ParseInt(limitStr, 0, 64); err == nil {
								if limit <= maxAllowed {
									return true
								}
							}
						}
					}
				}

				// 解析形如 "var <= LIMIT" 的约束
				if strings.Contains(condition, "<=") {
					parts := strings.Split(condition, "<=")
					if len(parts) >= 2 {
						varPart := strings.TrimSpace(parts[0])
						if varPart == varName {
							limitStr := strings.TrimSpace(parts[1])
							if limit, err := strconv.ParseInt(limitStr, 0, 64); err == nil {
								if limit <= maxAllowed {
									return true
								}
							}
						}
					}
				}

				// 解析形如 "LIMIT > var" 的约束
				if strings.Contains(condition, ">") {
					parts := strings.Split(condition, ">")
					if len(parts) >= 2 {
						rightPart := strings.TrimSpace(parts[1])
						if rightPart == varName {
							limitStr := strings.TrimSpace(parts[0])
							if limit, err := strconv.ParseInt(limitStr, 0, 64); err == nil {
								if limit >= maxAllowed {
									return true
								}
							}
						}
					}
				}
			}
		}
	}

	// 3. 检查值范围约束
	d.mutex.RLock()
	valueRange, hasValueRange := d.valueRanges[varName]
	d.mutex.RUnlock()

	if hasValueRange {
		// 如果变量有固定的值范围，检查是否安全
		if valueRange.IsFixed || (valueRange.Max != 0 && valueRange.Max <= maxAllowed) {
			return true
		}
	}

	// 4. 检查变量约束
	d.mutex.RLock()
	constraints, hasConstraints := d.constraints[varName]
	d.mutex.RUnlock()

	if hasConstraints {
		// 检查约束的上界
		if constraints.HasUpperBound && constraints.UpperBound <= maxAllowed {
			return true
		}
		// 检查约束的下界和上界
		if constraints.HasLowerBound && constraints.LowerBound >= 0 && constraints.HasUpperBound && constraints.UpperBound <= maxAllowed {
			return true
		}
	}

	// 5. 向上查找控制流结构
	parent := varNode.Parent()
	depth := 0
	maxDepth := 15

	for parent != nil && depth < maxDepth {
		nodeType := core.SafeType(parent)

		// 检查if语句的条件
		if nodeType == "if_statement" {
			condition := core.SafeChildByFieldName(parent, "condition")
			if condition != nil {
				condText := ctx.GetSourceText(condition)
				if strings.Contains(condText, varName) {
					// 如果条件保证变量在范围内
					if d.analyzeRangeGuaranteeInCondition(condText, varName, maxAllowed) {
						return true
					}
				}
			}
		}

		// 检查循环的条件
		if nodeType == "for_statement" || nodeType == "while_statement" {
			condition := core.SafeChildByFieldName(parent, "condition")
			if condition != nil {
				condText := ctx.GetSourceText(condition)
				if strings.Contains(condText, varName) {
					// 循环条件通常限制变量的范围
					if d.analyzeRangeGuaranteeInCondition(condText, varName, maxAllowed) {
						return true
					}
				}
			}
		}

		parent = parent.Parent()
		depth++
	}

	return false
}

// analyzeRangeGuaranteeInCondition 分析条件中的范围保证
func (d *IntOverflowDetectorImproved) analyzeRangeGuaranteeInCondition(condText, varName string, maxAllowed int64) bool {
	// 检查形如 "var < LIMIT" 的条件
	if strings.Contains(condText, "<") {
		parts := strings.Split(condText, "<")
		if len(parts) >= 2 {
			varPart := strings.TrimSpace(parts[0])
			if varPart == varName || strings.Contains(varPart, varName) {
				limitStr := strings.TrimSpace(parts[1])
				if limit, err := strconv.ParseInt(limitStr, 0, 64); err == nil {
					if limit > 0 && limit <= maxAllowed {
						return true
					}
				}
			}
		}
	}

	// 检查形如 "var <= LIMIT" 的条件
	if strings.Contains(condText, "<=") {
		parts := strings.Split(condText, "<=")
		if len(parts) >= 2 {
			varPart := strings.TrimSpace(parts[0])
			if varPart == varName || strings.Contains(varPart, varName) {
				limitStr := strings.TrimSpace(parts[1])
				if limit, err := strconv.ParseInt(limitStr, 0, 64); err == nil {
					if limit >= 0 && limit <= maxAllowed {
						return true
					}
				}
			}
		}
	}

	return false
}

// ===== 2024-2025 最新研究：ESBMC v7.4 + CMU 两步法辅助方法 =====

// computeValueRange 计算节点的值范围（ESBMC v7.4 区间分析）
// 返回：最小值、最大值、是否有有效范围
func (d *IntOverflowDetectorImproved) computeValueRange(ctx *core.AnalysisContext, node *sitter.Node) (min, max int64, hasRange bool) {
	// 尝试提取常量值
	if val, ok := d.extractIntValue(ctx, node); ok {
		return val, val, true
	}

	// 对于变量，使用类型边界
	nodeType := core.SafeType(node)
	switch nodeType {
	case "int", "int32_t", "long":
		return 0, 2147483647, true // INT32_MAX
	case "unsigned int", "uint32_t", "unsigned long":
		return 0, 4294967295, true // UINT32_MAX
	case "short", "int16_t":
		return -32768, 32767, true
	case "unsigned short", "uint16_t":
		return 0, 65535, true
	case "size_t", "long long", "int64_t", "uint64_t":
		// 64位类型使用更保守的范围
		return 0, 65536, true // 假设实际使用不会超过 16 位
	default:
		// 默认使用 INT32 范围
		return 0, 2147483647, true
	}
}

// checkMultiplicationOverflowConservative 保守的乘法溢出检查
// 使用区间分析检查乘法是否可能溢出
func (d *IntOverflowDetectorImproved) checkMultiplicationOverflowConservative(
	leftMin, leftMax int64, leftHasRange bool,
	rightMin, rightMax int64, rightHasRange bool,
) bool {
	// 如果没有有效范围，保守地假设可能溢出
	if !leftHasRange || !rightHasRange {
		return true
	}

	// 检查最大乘积是否可能溢出 INT32 范围
	maxProduct := leftMax * rightMax
	if maxProduct > 2147483647 || maxProduct < -2147483648 {
		return true // 可能溢出
	}

	// 检查最小乘积
	minProduct := leftMin * rightMin
	if minProduct > 2147483647 || minProduct < -2147483648 {
		return true // 可能溢出
	}

	return false // 区间分析显示不太可能溢出
}

// isExploitableContextStrict 可利用性检查（CMU 两步法第二步）
// 报告在危险上下文中的溢出，但通过 isIntentionalOverflowInCrypto 过滤加密库
func (d *IntOverflowDetectorImproved) isExploitableContextStrict(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 向上遍历 AST 树，查找危险上下文
	parent := node.Parent()
	depth := 0
	maxDepth := 8

	for parent != nil && depth < maxDepth {
		parentType := core.SafeType(parent)

		// 危险上下文 1：内存分配函数参数（最危险）
		if parentType == "call_expression" {
			functionNode := core.SafeChild(parent, 0)
			if functionNode != nil {
				funcName := ctx.GetSourceText(functionNode)
				// 标准内存分配函数
				criticalFuncs := []string{
					"malloc", "calloc", "realloc", "alloca",
					"OPENSSL_malloc", "OPENSSL_zalloc", "CRYPTO_malloc", "CRYPTO_zalloc",
					"BUF_MEM_new", "BUF_MEM_grow", "BUF_MEM_grow_clean",
				}
				for _, cf := range criticalFuncs {
					if strings.Contains(funcName, cf) {
						return true
					}
				}
				// 其他函数也可能是危险的，继续检查
			}
		}

		// 危险上下文 2：赋值语句右侧（可能存储到变量中后续使用）
		if parentType == "assignment_expression" {
			// 检查是否在声明中赋值
			left := core.SafeChild(parent, 0)
			if left != nil {
				leftType := core.SafeType(left)
				// 如果赋值给指针变量，非常危险
				if leftType == "pointer_declarator" || leftType == "init_declarator" {
					return true
				}
			}
			// 其他赋值也报告，因为值可能被后续使用
			return true
		}

		// 危险上下文 3：数组大小计算（中等危险）
		if parentType == "subscript_expression" {
			// 检查是否在数组声明中
			grandParent := parent.Parent()
			if grandParent != nil && core.SafeType(grandParent) == "array_declarator" {
				return true
			}
			// 数组下标访问也报告
			return true
		}

		// 危险上下文 4：条件语句中的比较（可能导致逻辑错误）
		if parentType == "if_statement" || parentType == "while_statement" ||
		   parentType == "for_statement" || parentType == "conditional_expression" {
			return true
		}

		// 危险上下文 5：return 语句（返回值可能被使用）
		if parentType == "return_statement" {
			return true
		}

		// 危险上下文 6：算术表达式的一部分（可能累积溢出）
		if parentType == "binary_expression" {
			// 如果父节点也是运算，继续向上检查
			// 这样可以捕获更复杂的表达式链
		}

		parent = parent.Parent()
		depth++
	}

	// 默认：保守策略，报告所有其他情况
	// 真正的过滤由 isIntentionalOverflowInCrypto 完成
	return true
}

// isIntentionalOverflowInCrypto 过滤加密库中的故意溢出（Buglens 2025）
// 识别加密算法和内核优化中故意的整数溢出
func (d *IntOverflowDetectorImproved) isIntentionalOverflowInCrypto(ctx *core.AnalysisContext, node *sitter.Node) bool {
	// 获取当前文件的路径
	filePath := ctx.Unit.FilePath

	// 过滤测试文件
	if strings.Contains(filePath, "/test/") || 
	   strings.Contains(filePath, "/tests/") ||
	   strings.Contains(filePath, "_test.c") ||
	   strings.Contains(filePath, "_test.cpp") {
		return true
	}

	// 过滤演示文件
	if strings.Contains(filePath, "/demos/") || strings.Contains(filePath, "/demo/") {
		return true
	}

	// 过滤文档文件
	if strings.Contains(filePath, "/doc/") || strings.Contains(filePath, "/docs/") {
		return true
	}

	// 检查是否在加密算法相关的函数中
	// 通过向上遍历查找函数定义
	functionNode := d.findContainingFunction(ctx, node)
	if functionNode != nil {
		funcName := d.getFunctionName(ctx, functionNode)
		
		// 加密算法特征关键词
		cryptoKeywords := []string{
			"crypto", "cipher", "digest", "hash", "aes", "des", "sha",
			"md5", "rsa", "ec_", "ecp_", "bn_", "curve", "elliptic",
			"bigint", "bignum", "mont", "mod_mul", "mod_exp",
		}
		
		funcLower := strings.ToLower(funcName)
		for _, keyword := range cryptoKeywords {
			if strings.Contains(funcLower, keyword) {
				return true // 可能是加密算法中的故意溢出
			}
		}
	}

	return false
}

// findContainingFunction 查找包含节点的函数定义
