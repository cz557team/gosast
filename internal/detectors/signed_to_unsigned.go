package detectors

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// NumericRange 表示数值的取值范围
type NumericRange struct {
	Min   int64 // 最小值
	Max   int64 // 最大值
	IsTop bool  // 是否为Top（未知范围）
}

// NewNumericRange 创建一个新的数值范围
func NewNumericRange(min, max int64) *NumericRange {
	return &NumericRange{
		Min:   min,
		Max:   max,
		IsTop: false,
	}
}

// NewTopRange 创建一个Top范围（未知）
func NewTopRange() *NumericRange {
	return &NumericRange{
		IsTop: true,
	}
}

// ContainsNegative 检查范围是否包含负数
func (r *NumericRange) ContainsNegative() bool {
	if r.IsTop {
		return true // 未知范围假设可能包含负数
	}
	return r.Min < 0
}

// Intersect 计算两个范围的交集
func (r *NumericRange) Intersect(other *NumericRange) *NumericRange {
	if r.IsTop {
		return other
	}
	if other.IsTop {
		return r
	}

	return NewNumericRange(
		max(r.Min, other.Min),
		min(r.Max, other.Max),
	)
}

// Union 计算两个范围的并集
func (r *NumericRange) Union(other *NumericRange) *NumericRange {
	if r.IsTop || other.IsTop {
		return NewTopRange()
	}

	return NewNumericRange(
		min(r.Min, other.Min),
		max(r.Max, other.Max),
	)
}

// String 返回范围的字符串表示
func (r *NumericRange) String() string {
	if r.IsTop {
		return "[-∞, +∞]"
	}
	return fmt.Sprintf("[%d, %d]", r.Min, r.Max)
}

// VariableInfo 变量信息
type VariableInfo struct {
	Name           string        // 变量名
	Type           string        // 变量类型
	IsSigned       bool          // 是否有符号
	Range          *NumericRange // 数值范围
	IsTainted      bool          // 是否被污染
	Declaration    *sitter.Node  // 声明节点
	IdentifierNode *sitter.Node  // 标识符节点（用于污点传播）
}

// TypeConversion 类型转换信息
type TypeConversion struct {
	FromType    string        // 源类型
	ToType      string        // 目标类型
	FromSigned  bool          // 源类型是否有符号
	ToSigned    bool          // 目标类型是否有符号
	Line        int           // 行号
	Node        *sitter.Node  // AST节点
	Function    string        // 所在函数
	SourceVar   string        // 源变量名
	SourceRange *NumericRange // 源变量的推导范围
	IsTainted   bool          // 源变量是否被污染
}

// SignedToUnsignedDetector CWE-195检测器
type SignedToUnsignedDetector struct {
	*core.BaseDetector
	variables    map[string]*VariableInfo // 变量信息
	variablesMu  sync.RWMutex             // 保护 variables map 的并发访问
	conversions  []TypeConversion         // 类型转换记录
	taintSources []string                 // 污染源函数列表
}

// NewSignedToUnsignedDetector 创建检测器
func NewSignedToUnsignedDetector() *SignedToUnsignedDetector {
	return &SignedToUnsignedDetector{
		BaseDetector: core.NewBaseDetector(
			"Signed to Unsigned Detector",
			"Detects CWE-195: Signed to Unsigned Conversion Errors using abstract interpretation and taint analysis",
		),
		variables:    make(map[string]*VariableInfo),
		conversions:  make([]TypeConversion, 0),
		taintSources: []string{"read", "recv", "recvfrom", "fgets", "getc", "getchar", "argv", "argc"},
	}
}

// Run 运行检测器
func (d *SignedToUnsignedDetector) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	// 获取全局锁，防止并发访问 variables map
	d.variablesMu.Lock()
	defer d.variablesMu.Unlock()

	var vulns []core.DetectorVulnerability

	// 清空之前的变量映射（每个文件重新初始化）
	d.variables = make(map[string]*VariableInfo)
	d.conversions = d.conversions[:0] // 清空转换记录

	// *** 改进 ***: 执行跨函数污点传播
	ctx.InitTaintEngine()
	if err := ctx.RunCrossFunctionTaintPropagation(); err != nil {
		// 跨函数污点传播失败不是致命错误，继续执行
		fmt.Printf("[Warning] Cross-function taint propagation failed: %v\n", err)
	}

	// 1. 收集所有变量声明和类型信息
	d.collectVariables(ctx)

	// 2. 执行初始数值范围分析（抽象解释）
	d.performRangeAnalysis(ctx)

	// 3. 执行初始污点分析（标记 user_value 等变量为污点）
	d.performTaintAnalysis(ctx)

	// *** 关键改进 ***: 在污点分析之后，再次执行跨函数污点传播
	// 因为 performTaintAnalysis 可能标记了新的污点变量（如 user_value）
	// 这些变量需要被传播到函数参数
	if err := ctx.RunCrossFunctionTaintPropagation(); err != nil {
		fmt.Printf("[Warning] Second cross-function taint propagation failed: %v\n", err)
	}

	// *** 关键改进 ***: 在跨函数传播之后，更新变量的 IsTainted 字段
	// 因为跨函数传播可能将污点传播到函数参数，需要更新 d.variables 中的 IsTainted
	d.updateTaintedVariablesFromEngine(ctx)

	// 4. 如果有 CFG，执行路径敏感的分析
	if ctx.CFG != nil && len(ctx.CFG.Nodes) > 0 {
		d.performPathSensitiveAnalysis(ctx)
	}

	// 5. 检测类型转换
	d.detectConversions(ctx)

	// 6. 识别漏洞（有符号转无符号 + 范围包含负数 + 无保护）
	for _, conv := range d.conversions {
		// 首先检查基本的漏洞条件
		if !d.isVulnerableConversion(conv) {
			continue
		}

		// 检查是否有保护性条件语句
		// 如果有 if (x >= 0) 这样的保护，则不报告漏洞
		if d.isProtectedByCondition(ctx, conv) {
			continue
		}

		vuln := d.createVulnerability(ctx, conv)
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// collectVariables 收集所有变量声明
func (d *SignedToUnsignedDetector) collectVariables(ctx *core.AnalysisContext) {
	// 查找所有变量声明（带初始化）
	query := `(declaration
		declarator: (init_declarator
			declarator: (identifier) @name
		) @initdecl
	) @decl`

	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	for _, match := range matches {
		declNode := match.Node
		nameMatch := match.Captures["name"]

		if nameMatch == nil {
			continue
		}

		varName := ctx.GetSourceText(nameMatch)
		varType := d.extractVariableType(ctx, declNode)
		isSigned := d.isSignedType(varType)

		d.variables[varName] = &VariableInfo{
			Name:           varName,
			Type:           varType,
			IsSigned:       isSigned,
			Range:          d.getInitialRange(varType),
			IsTainted:      false,
			Declaration:    declNode,
			IdentifierNode: nameMatch,
		}
	}

	// 查找所有函数参数（parameter_declaration）
	paramQuery := `(parameter_declaration
		declarator: (identifier) @param_name
	) @param`

	paramMatches, err := ctx.Query(paramQuery)
	if err != nil {
		return
	}

	for _, match := range paramMatches {
		paramNode := match.Node
		nameMatch := match.Captures["param_name"]

		if nameMatch == nil {
			continue
		}

		paramName := ctx.GetSourceText(nameMatch)
		paramType := d.extractVariableType(ctx, paramNode)
		isSigned := d.isSignedType(paramType)

		d.variables[paramName] = &VariableInfo{
			Name:           paramName,
			Type:           paramType,
			IsSigned:       isSigned,
			Range:          d.getInitialRange(paramType),
			IsTainted:      false, // 函数参数初始未污染，后续通过污点分析更新
			Declaration:    paramNode,
			IdentifierNode: nameMatch,
		}
	}
}

// performRangeAnalysis 执行数值范围分析（抽象解释的核心）
func (d *SignedToUnsignedDetector) performRangeAnalysis(ctx *core.AnalysisContext) {
	// 查找所有赋值表达式
	query := `(assignment_expression
		left: (identifier) @var
		right: _ @value
	) @assign`

	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	for _, match := range matches {
		varMatch := match.Captures["var"]
		valueMatch := match.Captures["value"]

		if varMatch == nil || valueMatch == nil {
			continue
		}

		varName := ctx.GetSourceText(varMatch)
		varInfo := d.variables[varName]
		if varInfo == nil {
			continue
		}

		// 分析右侧表达式，推导数值范围
		newRange := d.analyzeExpressionRange(ctx, valueMatch)
		if newRange != nil {
			varInfo.Range = newRange
		}
	}

	// 查找所有算术运算并更新范围
	d.analyzeArithmeticOperations(ctx)
}

// analyzeExpressionRange 分析表达式的数值范围
func (d *SignedToUnsignedDetector) analyzeExpressionRange(ctx *core.AnalysisContext, exprNode *sitter.Node) *NumericRange {
	if exprNode == nil {
		return NewTopRange()
	}

	switch core.SafeType(exprNode) {
	case "number_literal":
		// 解析数字字面量
		text := ctx.GetSourceText(exprNode)
		text = strings.TrimSpace(text)
		val, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return NewTopRange()
		}
		return NewNumericRange(val, val)

	case "identifier":
		// 查找变量的已知范围
		varName := ctx.GetSourceText(exprNode)
		if varInfo, ok := d.variables[varName]; ok {
			return varInfo.Range
		}
		return NewTopRange()

	case "unary_expression":
		// 处理一元表达式（如 -x, +x, ~x）
		operator := d.getUnaryOperator(exprNode)
		operand := d.getUnaryOperand(exprNode)

		if operand == nil {
			return NewTopRange()
		}

		operandRange := d.analyzeExpressionRange(ctx, operand)
		if operandRange.IsTop {
			return NewTopRange()
		}

		switch operator {
		case "-":
			// 取反：[-10, 20] -> [-20, 10]
			return NewNumericRange(-operandRange.Max, -operandRange.Min)
		case "+":
			return operandRange
		case "~":
			// 按位取反：范围难以精确推导，保守返回Top
			return NewTopRange()
		default:
			return NewTopRange()
		}

	case "binary_expression":
		// 处理二元表达式（如 x + y, x - y, x * y）
		left := d.getBinaryLeft(exprNode)
		right := d.getBinaryRight(exprNode)
		operator := d.getBinaryOperator(exprNode)

		if left == nil || right == nil {
			return NewTopRange()
		}

		leftRange := d.analyzeExpressionRange(ctx, left)
		rightRange := d.analyzeExpressionRange(ctx, right)

		return d.computeBinaryRange(leftRange, rightRange, operator)

	default:
		return NewTopRange()
	}
}

// computeBinaryRange 计算二元表达式的结果范围
func (d *SignedToUnsignedDetector) computeBinaryRange(left, right *NumericRange, operator string) *NumericRange {
	if left.IsTop || right.IsTop {
		return NewTopRange()
	}

	switch operator {
	case "+":
		// 加法：[a, b] + [c, d] = [a+c, b+d]
		return NewNumericRange(left.Min+right.Min, left.Max+right.Max)

	case "-":
		// 减法：[a, b] - [c, d] = [a-d, b-c]
		return NewNumericRange(left.Min-right.Max, left.Max-right.Min)

	case "*":
		// 乘法：需要考虑所有组合
		combinations := []int64{
			left.Min * right.Min,
			left.Min * right.Max,
			left.Max * right.Min,
			left.Max * right.Max,
		}
		minVal := combinations[0]
		maxVal := combinations[0]
		for _, val := range combinations {
			if val < minVal {
				minVal = val
			}
			if val > maxVal {
				maxVal = val
			}
		}
		return NewNumericRange(minVal, maxVal)

	case "/":
		// 除法：简化处理，避免除零
		if right.Min == 0 || right.Max == 0 {
			return NewTopRange()
		}
		// 保守估计：最小可能除最大，最大可能除最小
		minVal := min64(
			left.Min/right.Max,
			left.Max/right.Max,
			left.Min/right.Min,
			left.Max/right.Min,
		)
		maxVal := max64(
			left.Min/right.Max,
			left.Max/right.Max,
			left.Min/right.Min,
			left.Max/right.Min,
		)
		return NewNumericRange(minVal, maxVal)

	case "%":
		// 取模：结果范围取决于右操作数
		if right.Min < 0 {
			return NewTopRange()
		}
		return NewNumericRange(0, right.Max-1)

	default:
		return NewTopRange()
	}
}

// analyzeArithmeticOperations 分析算术运算并更新变量范围
func (d *SignedToUnsignedDetector) analyzeArithmeticOperations(ctx *core.AnalysisContext) {
	// 查找 +=, -=, *=, /= 等复合赋值
	query := `(assignment_expression
		left: (identifier) @var
		right: (binary_expression) @expr
	) @assign`

	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	for _, match := range matches {
		varMatch := match.Captures["var"]
		exprMatch := match.Captures["expr"]

		if varMatch == nil || exprMatch == nil {
			continue
		}

		varName := ctx.GetSourceText(varMatch)
		varInfo := d.variables[varName]
		if varInfo == nil {
			continue
		}

		// 分析表达式
		newRange := d.analyzeExpressionRange(ctx, exprMatch)
		if newRange != nil {
			varInfo.Range = newRange
		}
	}
}

// performTaintAnalysis 执行污点分析（使用跨函数污点传播）
func (d *SignedToUnsignedDetector) performTaintAnalysis(ctx *core.AnalysisContext) {
	// *** 改进 ***: 使用跨函数污点传播来标记变量
	if ctx.Taint != nil {
		engine := ctx.Taint.(*core.MemoryTaintEngine)
		// 遍历所有变量，检查是否在跨函数污点传播中被标记
		for varName, varInfo := range d.variables {
			currentFuncName := ctx.GetContainingFunctionName(varInfo.Declaration)

			// *** 关键改进 ***: 检查带初始化的声明，如果初始化表达式被污点传播，则变量也被污点传播
			if varInfo.Declaration != nil {
				initDecl := varInfo.Declaration.ChildByFieldName("declarator")
				if initDecl != nil && initDecl.Type() == "init_declarator" {
					initValue := initDecl.ChildByFieldName("value")
					if initValue != nil {
						// *** 关键 ***: 检查 call_expression 的参数是否被污点传播
						// 如果参数是污点，则返回值也视为污点
						if initValue.Type() == "call_expression" {
							args := initValue.ChildByFieldName("arguments")
							if args != nil {
								hasTaintedArg := false
								for i := 0; i < int(args.ChildCount()); i++ {
									arg := args.Child(i)
									if arg != nil && arg.Type() != "(" && arg.Type() != ")" {
										if engine.IsTainted(arg) {
											hasTaintedArg = true
											break
										}
									}
								}
								if hasTaintedArg {
									d.variables[varName].IsTainted = true
									// *** 关键改进 ***: 同时标记 identifier 节点为污点，用于跨函数传播
									if varInfo.IdentifierNode != nil && currentFuncName != "" {
										engine.MarkNodeTainted(varInfo.IdentifierNode, currentFuncName)
									}
								}
							}
						} else {
							// 其他类型的初始化表达式，如果被污点传播，则变量也被污点传播
							isInitTainted := engine.IsTainted(initValue)
							if isInitTainted {
								d.variables[varName].IsTainted = true
							}
						}
					}
				}
			}

			// 查找变量的声明节点
			if varInfo.Declaration != nil {
				// 检查变量是否被污染（通过跨函数传播）
				identifierNode := d.findIdentifierInDeclaration(varInfo.Declaration, varName)
				if identifierNode != nil {
					if currentFuncName != "" {
						isTainted := engine.IsIdentifierTaintedInFunction(identifierNode, currentFuncName)
						if isTainted {
							// *** 修复 ***: 直接更新 map 中的值
							d.variables[varName].IsTainted = true
						}
					}
				}
			}
		}
	}

	// 查找所有函数调用（原有逻辑）
	query := `(call_expression
		function: (identifier) @func
	) @call`

	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	for _, match := range matches {
		funcMatch := match.Captures["func"]
		if funcMatch == nil {
			continue
		}

		funcName := ctx.GetSourceText(funcMatch)

		// 检查是否是污染源
		if d.isTaintSource(funcName) {
			// 查找赋值目标
			parent := match.Node.Parent()
			if parent != nil && core.SafeType(parent) == "assignment_expression" {
				leftChild := core.SafeChild(parent, 0)
				if leftChild != nil && core.SafeType(leftChild) == "identifier" {
					varName := ctx.GetSourceText(leftChild)
					if varInfo, ok := d.variables[varName]; ok {
						varInfo.IsTainted = true
					}
				}
			}
		}
	}

	// 简单的污点传播：如果一个变量被污染的变量赋值，则也被污染
	d.propagateTaint(ctx)
}

// findIdentifierInDeclaration 在声明节点中查找标识符
func (d *SignedToUnsignedDetector) findIdentifierInDeclaration(declNode *sitter.Node, varName string) *sitter.Node {
	if declNode == nil {
		return nil
	}

	// 需要一个临时的 context 来获取源文本
	// 由于我们没有 ctx 参数，这里简化实现：直接返回第一个 identifier
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if core.SafeType(child) == "identifier" {
			return child
		}
		// 递归查找
		if found := d.findIdentifierInDeclaration(child, varName); found != nil {
			return found
		}
	}

	return nil
}

// updateTaintedVariablesFromEngine 从污点引擎更新变量的 IsTainted 字段
// 用于在跨函数传播后，将污点引擎的污点标记同步到 d.variables
func (d *SignedToUnsignedDetector) updateTaintedVariablesFromEngine(ctx *core.AnalysisContext) {
	if ctx.Taint == nil {
		return
	}

	engine := ctx.Taint.(*core.MemoryTaintEngine)

	// 遍历所有变量，检查是否在污点引擎中被标记
	for varName, varInfo := range d.variables {
		if varInfo.IdentifierNode != nil {
			currentFuncName := ctx.GetContainingFunctionName(varInfo.Declaration)
			if currentFuncName != "" {
				// 检查标识符在函数作用域内是否被污点传播
				if engine.IsIdentifierTaintedInFunction(varInfo.IdentifierNode, currentFuncName) {
					d.variables[varName].IsTainted = true
				}
			}
		}
	}
}

// propagateTaint 传播污点标记
func (d *SignedToUnsignedDetector) propagateTaint(ctx *core.AnalysisContext) {
	changed := true
	for changed {
		changed = false

		// 1. 简单赋值传播：x = y (如果 y 被污染，x 也被污染)
		changed = d.propagateTaintViaAssignment(ctx) || changed

		// 2. 函数调用传播：x = foo(y) (如果 y 被污染，x 可能被污染)
		changed = d.propagateTaintViaCall(ctx) || changed

		// 3. 算术运算传播：x = y + z (如果 y 或 z 被污染，x 被污染)
		changed = d.propagateTaintViaArithmetic(ctx) || changed
	}
}

// propagateTaintViaAssignment 通过赋值传播污点
func (d *SignedToUnsignedDetector) propagateTaintViaAssignment(ctx *core.AnalysisContext) bool {
	changed := false

	query := `(assignment_expression
		left: (identifier) @left
		right: (identifier) @right
	) @assign`

	matches, err := ctx.Query(query)
	if err != nil {
		return false
	}

	for _, match := range matches {
		leftMatch := match.Captures["left"]
		rightMatch := match.Captures["right"]

		if leftMatch == nil || rightMatch == nil {
			continue
		}

		leftVar := ctx.GetSourceText(leftMatch)
		rightVar := ctx.GetSourceText(rightMatch)

		leftInfo := d.variables[leftVar]
		rightInfo := d.variables[rightVar]

		if leftInfo == nil || rightInfo == nil {
			continue
		}

		// 如果右侧被污染，左侧也标记为污染
		if rightInfo.IsTainted && !leftInfo.IsTainted {
			leftInfo.IsTainted = true
			changed = true
		}
	}

	return changed
}

// propagateTaintViaCall 通过函数调用传播污点
func (d *SignedToUnsignedDetector) propagateTaintViaCall(ctx *core.AnalysisContext) bool {
	changed := false

	// 查找函数调用赋值：x = func(...)
	query := `(assignment_expression
		left: (identifier) @left
		right: (call_expression) @call
	) @assign`

	matches, err := ctx.Query(query)
	if err != nil {
		return false
	}

	for _, match := range matches {
		leftMatch := match.Captures["left"]
		callMatch := match.Captures["call"]

		if leftMatch == nil || callMatch == nil {
			continue
		}

		leftVar := ctx.GetSourceText(leftMatch)
		leftInfo := d.variables[leftVar]
		if leftInfo == nil {
			continue
		}

		// 检查函数参数中是否有被污染的变量
		hasTaintedArg := false
		if core.SafeChildCount(callMatch) >= 2 {
			argList := core.SafeChild(callMatch, 1) // argument_list
			if argList != nil && core.SafeType(argList) == "argument_list" {
				for i := uint32(0); i < core.SafeChildCount(argList); i++ {
					arg := core.SafeChild(argList, int(i))
					if arg != nil && core.SafeType(arg) == "identifier" {
						argName := ctx.GetSourceText(arg)
						if argInfo, ok := d.variables[argName]; ok && argInfo.IsTainted {
							hasTaintedArg = true
							break
						}
					}
				}
			}
		}

		// 如果有被污染的参数，返回值也可能被污染（保守估计）
		if hasTaintedArg && !leftInfo.IsTainted {
			leftInfo.IsTainted = true
			changed = true
		}
	}

	return changed
}

// propagateTaintViaArithmetic 通过算术运算传播污点
func (d *SignedToUnsignedDetector) propagateTaintViaArithmetic(ctx *core.AnalysisContext) bool {
	changed := false

	// 查找二元运算赋值：x = y op z
	query := `(assignment_expression
		left: (identifier) @left
		right: (binary_expression) @expr
	) @assign`

	matches, err := ctx.Query(query)
	if err != nil {
		return false
	}

	for _, match := range matches {
		leftMatch := match.Captures["left"]
		exprMatch := match.Captures["expr"]

		if leftMatch == nil || exprMatch == nil {
			continue
		}

		leftVar := ctx.GetSourceText(leftMatch)
		leftInfo := d.variables[leftVar]
		if leftInfo == nil {
			continue
		}

		// 检查操作数中是否有被污染的变量
		hasTaintedOperand := false
		for i := uint32(0); i < core.SafeChildCount(exprMatch); i++ {
			child := core.SafeChild(exprMatch, int(i))
			if child != nil && core.SafeType(child) == "identifier" {
				opName := ctx.GetSourceText(child)
				if opInfo, ok := d.variables[opName]; ok && opInfo.IsTainted {
					hasTaintedOperand = true
					break
				}
			}
		}

		// 如果有被污染的操作数，结果也被污染
		if hasTaintedOperand && !leftInfo.IsTainted {
			leftInfo.IsTainted = true
			changed = true
		}
	}

	return changed
}

// performPathSensitiveAnalysis 执行路径敏感的分析
// 使用 CFG 进行数据流分析，在每个条件节点精化变量范围
func (d *SignedToUnsignedDetector) performPathSensitiveAnalysis(ctx *core.AnalysisContext) {
	// 遍历所有 CFG 节点，查找条件节点
	for _, node := range ctx.CFG.Nodes {
		if node.Type == core.BlockCondition && node.Condition != nil {
			d.refineRangesAtCondition(ctx, node.Condition, node)
		}
	}
}

// refineRangesAtCondition 在条件语句处精化变量范围
// 例如：if (x >= 0) { ... }  // 在 then 分支中 x 的范围是 [0, +∞)
func (d *SignedToUnsignedDetector) refineRangesAtCondition(ctx *core.AnalysisContext, condNode *sitter.Node, cfgNode *core.CFGNode) {
	// condNode 可能是 condition_clause 或 binary_expression
	var binaryExpr *sitter.Node

	core.GlobalTreeSitterMutex.RLock()
	condType := core.SafeType(condNode)
	var childCount uint32
	if condType == "condition_clause" {
		childCount = core.SafeChildCount(condNode)
		if childCount >= 2 {
			binaryExpr = core.SafeChild(condNode, 1)
		}
	} else if condType == "binary_expression" {
		binaryExpr = condNode
	}
	core.GlobalTreeSitterMutex.RUnlock()

	if binaryExpr == nil || core.SafeType(binaryExpr) != "binary_expression" {
		return
	}

	// 提取条件和操作数（需要锁保护）
	core.GlobalTreeSitterMutex.RLock()
	leftNode := core.SafeChild(binaryExpr, 0)
	opNode := core.SafeChild(binaryExpr, 1)
	rightNode := core.SafeChild(binaryExpr, 2)
	core.GlobalTreeSitterMutex.RUnlock()

	if leftNode == nil || opNode == nil || rightNode == nil {
		return
	}

	op := ctx.GetSourceText(opNode)

	// 只处理标识符 vs 常量/表达式的比较
	if core.SafeType(leftNode) != "identifier" {
		return
	}

	varName := ctx.GetSourceText(leftNode)
	varInfo := d.variables[varName]
	if varInfo == nil || !varInfo.IsSigned {
		return
	}

	// 根据条件类型精化范围
	rightRange := d.analyzeExpressionRange(ctx, rightNode)
	if rightRange.IsTop {
		return
	}

	// 在 then 分支（条件为真时）精化范围
	d.refineRangeForTrueBranch(varInfo, op, rightRange)

	// 在 else 分支（条件为假时）精化范围
	// 注意：这里需要更复杂的 CFG 遍历来分别处理 then/else 分支
	// 当前实现为简化版本
}

// refineRangeForTrueBranch 根据条件为真时精化变量范围
func (d *SignedToUnsignedDetector) refineRangeForTrueBranch(varInfo *VariableInfo, op string, rightRange *NumericRange) {
	if varInfo.Range.IsTop || rightRange.IsTop {
		return
	}

	switch op {
	case ">":
		// x > c  =>  x 的范围是 [c+1, current_max]
		newMin := rightRange.Max + 1
		if newMin > varInfo.Range.Min {
			varInfo.Range.Min = newMin
		}

	case ">=":
		// x >= c  =>  x 的范围是 [c, current_max]
		if rightRange.Max > varInfo.Range.Min {
			varInfo.Range.Min = rightRange.Max
		}

	case "<":
		// x < c  =>  x 的范围是 [current_min, c-1]
		newMax := rightRange.Min - 1
		if newMax < varInfo.Range.Max {
			varInfo.Range.Max = newMax
		}

	case "<=":
		// x <= c  =>  x 的范围是 [current_min, c]
		if rightRange.Min < varInfo.Range.Max {
			varInfo.Range.Max = rightRange.Min
		}

	case "==":
		// x == c  =>  x 的范围是 [c, c]
		varInfo.Range.Min = rightRange.Min
		varInfo.Range.Max = rightRange.Max

	case "!=":
		// x != c  =>  范围分裂，保守处理不修改
		// 需要更复杂的数据流分析来处理不等式
	}
}

// detectConversions 检测类型转换
func (d *SignedToUnsignedDetector) detectConversions(ctx *core.AnalysisContext) {
	// 1. 检测显式类型转换：static_cast, reinterpret_cast, C-style cast
	d.detectExplicitCasts(ctx)

	// 2. 检测隐式类型转换：赋值、函数调用参数
	d.detectImplicitConversions(ctx)

	// 3. 检测比较表达式中的隐式转换（有符号 vs 无符号比较）
	d.detectComparisonConversions(ctx)
}

// detectExplicitCasts 检测显式类型转换
func (d *SignedToUnsignedDetector) detectExplicitCasts(ctx *core.AnalysisContext) {
	// C++ 风格转换（static_cast, reinterpret_cast, const_cast）
	// 注意：Tree-sitter 将这些解析为 call_expression

	// 查找所有 call_expression，然后在代码中过滤
	query := `(call_expression) @call`

	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	castFunctions := map[string]bool{
		"static_cast":      true,
		"reinterpret_cast": true,
		"const_cast":       true,
		"dynamic_cast":     true,
	}

	for _, match := range matches {
		callNode := match.Node
		callText := ctx.GetSourceText(callNode)

		// 检查是否是转换函数调用
		isCastFunc := false
		for funcName := range castFunctions {
			if strings.HasPrefix(callText, funcName+"<") {
				isCastFunc = true
				break
			}
		}

		if !isCastFunc {
			continue
		}

		// 提取参数（被转换的变量）
		varName := ""
		if core.SafeChildCount(callNode) > 1 {
			argList := core.SafeChild(callNode, 1)
			if argList != nil && core.SafeType(argList) == "argument_list" {
				// 获取第一个参数
				for i := 0; i < int(core.SafeChildCount(argList)); i++ {
					arg := core.SafeChild(argList, i)
					if arg != nil && core.SafeType(arg) == "identifier" {
						varName = ctx.GetSourceText(arg)
						break
					}
				}
			}
		}

		if varName == "" {
			continue
		}

		varInfo := d.variables[varName]
		if varInfo == nil {
			continue
		}
		if !varInfo.IsSigned {
			continue
		}

		// 提取目标类型
		toType := d.extractCastTargetType(callText)
		toSigned := d.isSignedType(toType)

		if !toSigned {
			// 记录有符号到无符号的转换
			parentFunc := d.findParentFunction(ctx, callNode)
			funcName := ""
			if parentFunc != nil {
				funcName = d.extractFunctionName(ctx, parentFunc)
			}

			d.conversions = append(d.conversions, TypeConversion{
				FromType:    varInfo.Type,
				ToType:      toType,
				FromSigned:  true,
				ToSigned:    false,
				Line:        int(callNode.StartPoint().Row) + 1,
				Node:        callNode,
				Function:    funcName,
				SourceVar:   varName,
				SourceRange: varInfo.Range,
				IsTainted:   varInfo.IsTainted,
			})
		}
	}
}

// detectImplicitConversions 检测隐式类型转换
func (d *SignedToUnsignedDetector) detectImplicitConversions(ctx *core.AnalysisContext) {
	// 查找赋值操作，检查类型不匹配
	query := `(assignment_expression
		left: (identifier) @left
		right: (identifier) @right
	) @assign`

	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	for _, match := range matches {
		leftMatch := match.Captures["left"]
		rightMatch := match.Captures["right"]

		if leftMatch == nil || rightMatch == nil {
			continue
		}

		leftVar := ctx.GetSourceText(leftMatch)
		rightVar := ctx.GetSourceText(rightMatch)

		leftInfo := d.variables[leftVar]
		rightInfo := d.variables[rightVar]

		if leftInfo == nil || rightInfo == nil {
			continue
		}

		// 检查是否是有符号到无符号的转换
		if rightInfo.IsSigned && !leftInfo.IsSigned {
			parentFunc := d.findParentFunction(ctx, match.Node)
			funcName := ""
			if parentFunc != nil {
				funcName = d.extractFunctionName(ctx, parentFunc)
			}

			d.conversions = append(d.conversions, TypeConversion{
				FromType:    rightInfo.Type,
				ToType:      leftInfo.Type,
				FromSigned:  true,
				ToSigned:    false,
				Line:        int(match.Node.StartPoint().Row) + 1,
				Node:        match.Node,
				Function:    funcName,
				SourceVar:   rightVar,
				SourceRange: rightInfo.Range,
				IsTainted:   rightInfo.IsTainted,
			})
		}
	}
}

// detectComparisonConversions 检测比较表达式中的隐式转换
// 这是 CWE-195 的常见形式：if (signed_var < unsigned_var)
func (d *SignedToUnsignedDetector) detectComparisonConversions(ctx *core.AnalysisContext) {
	// 查找所有 if_statement
	query := `(if_statement) @if`

	matches, err := ctx.Query(query)
	if err != nil {
		return
	}

	// 遍历 if_statement 查找 condition_clause
	for _, match := range matches {
		ifNode := match.Node

		// 查找 condition_clause 子节点
		for i := uint32(0); i < core.SafeChildCount(ifNode); i++ {
			child := core.SafeChild(ifNode, int(i))
			if child == nil || core.SafeType(child) != "condition_clause" {
				continue
			}

			// condition_clause 的第二个子节点(索引1)是 binary_expression
			// 子节点 0: '(', 子节点 1: binary_expression, 子节点 2: ')'
			if core.SafeChildCount(child) >= 2 {
				condNode := core.SafeChild(child, 1)
				if condNode == nil || core.SafeType(condNode) != "binary_expression" {
					continue
				}

				// 检查是否是比较运算
				if core.SafeChildCount(condNode) < 3 {
					continue
				}

				opNode := core.SafeChild(condNode, 1)
				if opNode == nil {
					continue
				}

				op := ctx.GetSourceText(opNode)
				comparisonOps := map[string]bool{
					"<": true, "<=": true, ">": true, ">=": true,
					"==": true, "!=": true,
				}

				if !comparisonOps[op] {
					continue
				}

				// 获取左右操作数
				leftNode := core.SafeChild(condNode, 0)
				rightNode := core.SafeChild(condNode, 2)

				if leftNode == nil || rightNode == nil {
					continue
				}

				// 处理变量 vs sizeof() 的比较（如 user_len < sizeof(buf)）
				if core.SafeType(leftNode) == "identifier" && core.SafeType(rightNode) == "sizeof_expression" {
					leftVarName := ctx.GetSourceText(leftNode)
					varInfo := d.variables[leftVarName]
					if varInfo != nil && varInfo.IsSigned && varInfo.Range.ContainsNegative() {
						parentFunc := d.findParentFunction(ctx, ifNode)
						funcName := ""
						if parentFunc != nil {
							funcName = d.extractFunctionName(ctx, parentFunc)
						}

						d.conversions = append(d.conversions, TypeConversion{
							FromType:    varInfo.Type,
							ToType:      "size_t",
							FromSigned:  true,
							ToSigned:    false,
							Line:        int(condNode.StartPoint().Row) + 1,
							Node:        condNode,
							Function:    funcName,
							SourceVar:   leftVarName,
							SourceRange: varInfo.Range,
							IsTainted:   varInfo.IsTainted,
						})
					}
				}

				// 处理 sizeof() vs 变量的比较（如 sizeof(buf) > user_len）
				if core.SafeType(leftNode) == "sizeof_expression" && core.SafeType(rightNode) == "identifier" {
					rightVarName := ctx.GetSourceText(rightNode)
					varInfo := d.variables[rightVarName]
					if varInfo != nil && varInfo.IsSigned && varInfo.Range.ContainsNegative() {
						parentFunc := d.findParentFunction(ctx, ifNode)
						funcName := ""
						if parentFunc != nil {
							funcName = d.extractFunctionName(ctx, parentFunc)
						}

						d.conversions = append(d.conversions, TypeConversion{
							FromType:    varInfo.Type,
							ToType:      "size_t",
							FromSigned:  true,
							ToSigned:    false,
							Line:        int(condNode.StartPoint().Row) + 1,
							Node:        condNode,
							Function:    funcName,
							SourceVar:   rightVarName,
							SourceRange: varInfo.Range,
							IsTainted:   varInfo.IsTainted,
						})
					}
				}
			}
		}
	}
}

// addComparisonConversion 添加比较转换记录
func (d *SignedToUnsignedDetector) addComparisonConversion(
	ctx *core.AnalysisContext,
	condNode *sitter.Node,
	signedInfo, unsignedInfo *VariableInfo,
	signedVar, unsignedVar, op string,
) {
	parentFunc := d.findParentFunction(ctx, condNode)
	funcName := ""
	if parentFunc != nil {
		funcName = d.extractFunctionName(ctx, parentFunc)
	}

	d.conversions = append(d.conversions, TypeConversion{
		FromType:    signedInfo.Type,
		ToType:      unsignedInfo.Type,
		FromSigned:  true,
		ToSigned:    false,
		Line:        int(condNode.StartPoint().Row) + 1,
		Node:        condNode,
		Function:    funcName,
		SourceVar:   signedVar,
		SourceRange: signedInfo.Range,
		IsTainted:   signedInfo.IsTainted,
	})
}

// getFunctionName 获取函数调用的函数名
func (d *SignedToUnsignedDetector) getFunctionName(ctx *core.AnalysisContext, callNode *sitter.Node) string {
	if callNode == nil || core.SafeType(callNode) != "call_expression" {
		return ""
	}

	// 获取 function 部分
	if core.SafeChildCount(callNode) > 0 {
		funcNode := core.SafeChild(callNode, 0)
		if funcNode != nil {
			// 处理 template_function: sizeof<size_t>
			if core.SafeType(funcNode) == "template_function" {
				for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
					child := core.SafeChild(funcNode, i)
					if child != nil && core.SafeType(child) == "type_identifier" {
						return ctx.GetSourceText(child)
					}
				}
			}
			// 处理 field_expression: obj.size()
			if core.SafeType(funcNode) == "field_expression" {
				for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
					child := core.SafeChild(funcNode, i)
					if child != nil && core.SafeType(child) == "field_identifier" {
						return ctx.GetSourceText(child)
					}
				}
			}
			// 处理简单的 identifier
			if core.SafeType(funcNode) == "identifier" {
				return ctx.GetSourceText(funcNode)
			}
		}
	}

	return ""
}

// isVulnerableConversion 判断转换是否漏洞
func (d *SignedToUnsignedDetector) isVulnerableConversion(conv TypeConversion) bool {
	// 核心判定规则：有符号转无符号 + 范围包含负数
	if !conv.FromSigned || conv.ToSigned {
		return false
	}

	// 检查源变量的范围是否包含负数
	if conv.SourceRange == nil || !conv.SourceRange.ContainsNegative() {
		return false
	}

	// TODO: 检查是否有保护性的条件语句
	// 这需要 AST 上下文，当前方法签名中没有 ctx
	// 需要在调用此方法之前进行检查

	return true
}

// isProtectedByCondition 检查转换是否被保护性条件语句保护
// 例如：if (x >= 0) { size_t y = x; }  // 被保护，不报告漏洞
func (d *SignedToUnsignedDetector) isProtectedByCondition(ctx *core.AnalysisContext, conv TypeConversion) bool {
	if conv.Node == nil {
		return false
	}

	// 向上遍历 AST，查找包含此转换的 if_statement
	node := conv.Node
	maxDepth := 20 // 限制向上查找的深度，避免无限循环

	for i := 0; i < maxDepth && node != nil; i++ {
		node = node.Parent()
		if node == nil {
			break
		}

		if core.SafeType(node) == "if_statement" {
			// 找到 if 语句，检查条件是否保护了变量
			if d.checkIfProtection(ctx, node, conv.SourceVar) {
				return true
			}
		}
	}

	return false
}

// checkIfProtection 检查 if 语句的条件是否保护了变量
// 返回 true 表示有保护（如 x >= 0），false 表示无保护或保护不充分
func (d *SignedToUnsignedDetector) checkIfProtection(ctx *core.AnalysisContext, ifNode *sitter.Node, varName string) bool {
	// 查找 if 语句的条件
	for i := uint32(0); i < core.SafeChildCount(ifNode); i++ {
		child := core.SafeChild(ifNode, int(i))
		if child == nil || core.SafeType(child) != "condition_clause" {
			continue
		}

		// condition_clause 的第二个子节点是条件表达式
		if core.SafeChildCount(child) >= 2 {
			condExpr := core.SafeChild(child, 1)
			if condExpr == nil {
				continue
			}

			// 检查是否是保护性条件：var >= 0, var > -1 等
			return d.isProtectiveCondition(ctx, condExpr, varName)
		}
	}

	return false
}

// isProtectiveCondition 检查条件是否保护了变量（确保其非负）
func (d *SignedToUnsignedDetector) isProtectiveCondition(ctx *core.AnalysisContext, condExpr *sitter.Node, varName string) bool {
	if core.SafeType(condExpr) != "binary_expression" {
		return false
	}

	leftNode := core.SafeChild(condExpr, 0)
	opNode := core.SafeChild(condExpr, 1)
	rightNode := core.SafeChild(condExpr, 2)

	if leftNode == nil || opNode == nil || rightNode == nil {
		return false
	}

	// 检查是否是变量在左侧
	if core.SafeType(leftNode) != "identifier" {
		return false
	}

	leftVar := ctx.GetSourceText(leftNode)
	if leftVar != varName {
		return false
	}

	op := ctx.GetSourceText(opNode)

	// 检查右侧是否是常量 0
	if core.SafeType(rightNode) != "number_literal" {
		return false
	}

	rightText := ctx.GetSourceText(rightNode)
	rightText = strings.TrimSpace(rightText)
	if rightText != "0" {
		return false
	}

	// 检查操作符是否是保护性的
	// >= 0, > -1 (但我们已经检查右侧是 0), == 0 (不充分，但保守处理)
	return op == ">=" || op == ">"
}

// createVulnerability 创建漏洞报告
func (d *SignedToUnsignedDetector) createVulnerability(ctx *core.AnalysisContext, conv TypeConversion) core.DetectorVulnerability {
	// 构建严重性等级
	severity := core.SeverityMedium
	confidence := core.ConfidenceMedium

	// 如果被污染，提升严重性
	if conv.IsTainted {
		severity = core.SeverityHigh
		confidence = core.ConfidenceHigh
	}

	// 如果范围确定包含负数，提升置信度
	if !conv.SourceRange.IsTop && conv.SourceRange.Min < 0 {
		confidence = core.ConfidenceHigh
	}

	taintInfo := ""
	if conv.IsTainted {
		taintInfo = " [TAINTED - from untrusted source]"
	}

	message := fmt.Sprintf("Signed to unsigned conversion error detected. Variable '%s' of type '%s' (range %s) is converted to unsigned type '%s'. This can cause wrap-around if the value is negative.%s",
		conv.SourceVar, conv.FromType, conv.SourceRange.String(), conv.ToType, taintInfo)

	return d.BaseDetector.CreateVulnerability(
		core.CWE195, // CWE-195: Signed to Unsigned Conversion Error
		message,
		conv.Node,
		confidence,
		severity,
	)
}

// ========== 辅助方法 ==========

// extractVariableType 提取变量类型
func (d *SignedToUnsignedDetector) extractVariableType(ctx *core.AnalysisContext, declNode *sitter.Node) string {
	for i := 0; i < int(core.SafeChildCount(declNode)); i++ {
		child := core.SafeChild(declNode, i)
		if child == nil {
			continue
		}

		// 跳过声明符
		if core.SafeType(child) == "declarator" || core.SafeType(child) == "init_declarator" {
			continue
		}

		text := ctx.GetSourceText(child)
		text = strings.TrimSpace(text)
		if len(text) > 50 {
			text = text[:50] + "..."
		}
		return text
	}
	return "unknown"
}

// isSignedType 判断类型是否有符号
func (d *SignedToUnsignedDetector) isSignedType(typeStr string) bool {
	typeStr = strings.TrimSpace(typeStr)
	typeStr = strings.ToLower(typeStr)

	// 无符号类型（包括常见的 typedef 别名）
	unsignedTypes := []string{
		"unsigned", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
		"size_t", "uintptr_t", "uintmax_t",
		"ulong", "uint", "ushort", "ubyte", // 常见无符号类型别名（zlib 等库使用）
		"u_long", "u_int", "u_short", "u_char", // BSD 风格无符号类型
		"z_crc_t", "z_off64_t", // zlib 特定无符号类型
	}

	for _, unsigned := range unsignedTypes {
		if strings.Contains(typeStr, unsigned) {
			return false
		}
	}

	// 如果明确指定了 unsigned，则为无符号
	if strings.HasPrefix(typeStr, "unsigned ") {
		return false
	}

	// 默认情况下，int, long, char 等是有符号的
	basicTypes := []string{"int", "long", "short", "char", "ptrdiff_t", "intptr_t", "ssize_t"}
	for _, basic := range basicTypes {
		if strings.Contains(typeStr, basic) {
			return true
		}
	}

	// 保守假设：未知类型视为有符号
	return true
}

// getInitialRange 获取类型的初始范围
func (d *SignedToUnsignedDetector) getInitialRange(typeStr string) *NumericRange {
	typeStr = strings.ToLower(strings.TrimSpace(typeStr))

	// 根据类型返回合理的范围
	switch {
	case strings.Contains(typeStr, "int8"):
		return NewNumericRange(math.MinInt8, math.MaxInt8)
	case strings.Contains(typeStr, "int16"):
		return NewNumericRange(math.MinInt16, math.MaxInt16)
	case strings.Contains(typeStr, "int32"):
		return NewNumericRange(math.MinInt32, math.MaxInt32)
	case strings.Contains(typeStr, "int64"):
		return NewNumericRange(math.MinInt64, math.MaxInt64)
	case strings.Contains(typeStr, "uint8"), strings.Contains(typeStr, "byte"):
		return NewNumericRange(0, math.MaxUint8)
	case strings.Contains(typeStr, "uint16"):
		return NewNumericRange(0, math.MaxUint16)
	case strings.Contains(typeStr, "uint32"):
		return NewNumericRange(0, math.MaxUint32)
	case strings.Contains(typeStr, "uint64"):
		// 使用最大int64值作为近似值
		return NewNumericRange(0, math.MaxInt64)
	case strings.Contains(typeStr, "size_t"):
		// size_t 通常是 64 位，使用最大int64作为近似
		return NewNumericRange(0, math.MaxInt64)
	case strings.Contains(typeStr, "int"):
		// 默认 int 假设为 32 位
		return NewNumericRange(math.MinInt32, math.MaxInt32)
	default:
		// 未知类型返回 Top
		return NewTopRange()
	}
}

// isTaintSource 检查是否是污染源
func (d *SignedToUnsignedDetector) isTaintSource(funcName string) bool {
	for _, source := range d.taintSources {
		if strings.Contains(funcName, source) {
			return true
		}
	}
	return false
}

// extractCastTargetType 从转换表达式中提取目标类型
func (d *SignedToUnsignedDetector) extractCastTargetType(castText string) string {
	// 处理 C++ 风格转换: static_cast<unsigned>(x)
	if strings.Contains(castText, "static_cast") {
		start := strings.Index(castText, "<") + 1
		end := strings.Index(castText, ">")
		if start > 0 && end > start {
			return strings.TrimSpace(castText[start:end])
		}
	}

	// 处理 C 风格转换: (unsigned int)x
	if strings.HasPrefix(castText, "(") {
		end := strings.Index(castText, ")")
		if end > 0 {
			return strings.TrimSpace(castText[1:end])
		}
	}

	return "unknown"
}

// getUnaryOperator 获取一元运算符
func (d *SignedToUnsignedDetector) getUnaryOperator(node *sitter.Node) string {
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if child != nil && (core.SafeType(child) == "-" || core.SafeType(child) == "+" || core.SafeType(child) == "~") {
			return core.SafeType(child)
		}
	}
	return ""
}

// getUnaryOperand 获取一元表达式的操作数
func (d *SignedToUnsignedDetector) getUnaryOperand(node *sitter.Node) *sitter.Node {
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		if child != nil && core.SafeType(child) == "identifier" || core.SafeType(child) == "number_literal" {
			return child
		}
	}
	return nil
}

// getBinaryLeft 获取二元表达式的左操作数
func (d *SignedToUnsignedDetector) getBinaryLeft(node *sitter.Node) *sitter.Node {
	if core.SafeChildCount(node) > 0 {
		return core.SafeChild(node, 0)
	}
	return nil
}

// getBinaryRight 获取二元表达式右操作数
func (d *SignedToUnsignedDetector) getBinaryRight(node *sitter.Node) *sitter.Node {
	if core.SafeChildCount(node) > 2 {
		return core.SafeChild(node, 2)
	}
	return nil
}

// getBinaryOperator 获取二元运算符
func (d *SignedToUnsignedDetector) getBinaryOperator(node *sitter.Node) string {
	if core.SafeChildCount(node) > 1 {
		op := core.SafeChild(node, 1)
		if op != nil {
			return core.SafeType(op)
		}
	}
	return ""
}

// findParentFunction 查找包含节点的函数
func (d *SignedToUnsignedDetector) findParentFunction(ctx *core.AnalysisContext, node *sitter.Node) *sitter.Node {
	parent := node.Parent()
	depth := 0
	maxDepth := 50

	for parent != nil && depth < maxDepth {
		if core.SafeType(parent) == "function_definition" {
			return parent
		}
		parent = parent.Parent()
		depth++
	}

	return nil
}

// extractFunctionName 提取函数名
func (d *SignedToUnsignedDetector) extractFunctionName(ctx *core.AnalysisContext, funcNode *sitter.Node) string {
	if funcNode == nil {
		return ""
	}

	for i := 0; i < int(core.SafeChildCount(funcNode)); i++ {
		child := core.SafeChild(funcNode, i)
		if core.SafeType(child) == "function_declarator" {
			for j := 0; j < int(core.SafeChildCount(child)); j++ {
				subChild := core.SafeChild(child, j)
				if core.SafeType(subChild) == "identifier" || core.SafeType(subChild) == "type_identifier" {
					return ctx.GetSourceText(subChild)
				}
			}
		}
	}
	return ""
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(vals ...int64) int64 {
	if len(vals) == 0 {
		return 0
	}
	minVal := vals[0]
	for _, v := range vals {
		if v < minVal {
			minVal = v
		}
	}
	return minVal
}

func max64(vals ...int64) int64 {
	if len(vals) == 0 {
		return 0
	}
	maxVal := vals[0]
	for _, v := range vals {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}
