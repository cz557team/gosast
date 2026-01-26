package core

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// FunctionSummary 函数摘要
// 描述函数的副作用：哪些参数被写入、哪些返回值被设置
type FunctionSummary struct {
	FuncName      string              // 函数名
	OutputParams  map[int]bool        // 输出参数索引 -> true
	Initializes   map[string]string   // 初始化的变量 -> 初始化位置描述
	HasSideEffects bool               // 是否有副作用
}

// FunctionSummaryManager 函数摘要管理器
// 用于跨函数的初始化分析（轻量级过程间分析）
type FunctionSummaryManager struct {
	summaries   map[string]*FunctionSummary  // 函数名 -> 摘要
	ctx         *AnalysisContext
}

// NewFunctionSummaryManager 创建函数摘要管理器
func NewFunctionSummaryManager(ctx *AnalysisContext) *FunctionSummaryManager {
	return &FunctionSummaryManager{
		summaries: make(map[string]*FunctionSummary),
		ctx:      ctx,
	}
}

// AnalyzeAll 分析所有函数并生成摘要
func (fsm *FunctionSummaryManager) AnalyzeAll() error {
	// 查找所有函数定义
	query := `(function_definition) @func`
	matches, err := fsm.ctx.Query(query)
	if err != nil {
		return err
	}

	// 为每个函数生成摘要
	for _, match := range matches {
		funcNode := match.Node

		// 获取函数名
		funcName := fsm.extractFunctionName(funcNode)
		if funcName == "" {
			continue
		}

		// 生成摘要
		summary := fsm.analyzeFunction(funcNode, funcName)
		fsm.summaries[funcName] = summary
	}

	return nil
}

// analyzeFunction 分析单个函数并生成摘要
func (fsm *FunctionSummaryManager) analyzeFunction(funcNode *sitter.Node, funcName string) *FunctionSummary {
	summary := &FunctionSummary{
		FuncName:      funcName,
		OutputParams:  make(map[int]bool),
		Initializes:   make(map[string]string),
		HasSideEffects: false,
	}

	// 1. 分析函数参数（查找指针参数，它们可能是输出参数）
	fsm.analyzeParameters(funcNode, summary)

	// 2. 分析函数体（查找赋值语句和函数调用）
	body := fsm.findFunctionBody(funcNode)
	if body != nil {
		fsm.analyzeFunctionBody(body, summary)
	}

	// 3. 如果是C标准库函数，使用预定义摘要
	fsm.applyKnownFunctionSummary(summary)

	return summary
}

// analyzeParameters 分析函数参数
func (fsm *FunctionSummaryManager) analyzeParameters(funcNode *sitter.Node, summary *FunctionSummary) {
	// 查找参数列表
	for i := 0; i < int(funcNode.ChildCount()); i++ {
		child := funcNode.Child(i)
		if child == nil {
			continue
		}

		if child.Type() == "parameter_list" || child.Type() == "parameter_declaration" {
			fsm.extractPointerParams(child, summary, 0)
		}
	}
}

// extractPointerParams 提取指针参数
func (fsm *FunctionSummaryManager) extractPointerParams(
	paramsNode *sitter.Node,
	summary *FunctionSummary,
	baseIndex int,
) {
	if paramsNode == nil {
		return
	}

	paramIndex := baseIndex

	for i := 0; i < int(paramsNode.ChildCount()); i++ {
		child := paramsNode.Child(i)
		if child == nil {
			continue
		}

		childType := child.Type()

		// 逗号分隔符
		if childType == "," {
			continue
		}

		// 参数声明
		if childType == "parameter_declaration" {
			// 检查是否是指针类型
			if fsm.isPointerParameter(child) {
				summary.OutputParams[paramIndex] = true
			}
			paramIndex++
		}

		// 嵌套的参数列表（递归）
		if childType == "parameter_list" {
			fsm.extractPointerParams(child, summary, paramIndex)
			break
		}
	}
}

// isPointerParameter 检查参数是否是指针
func (fsm *FunctionSummaryManager) isPointerParameter(paramDecl *sitter.Node) bool {
	if paramDecl == nil {
		return false
	}

	// 检查类型说明符
	for i := 0; i < int(paramDecl.ChildCount()); i++ {
		child := paramDecl.Child(i)
		if child == nil {
			continue
		}

		childType := child.Type()

		// pointer_declarator 直接表示指针
		if childType == "pointer_declarator" {
			return true
		}

		// 检查类型是否包含指针
		if childType == "type_qualifier" {
			text := fsm.ctx.GetSourceText(child)
			if text == "*" || text == "const*" || text == "*const" {
				return true
			}
		}
	}

	return false
}

// findFunctionBody 查找函数体
func (fsm *FunctionSummaryManager) findFunctionBody(funcNode *sitter.Node) *sitter.Node {
	for i := 0; i < int(funcNode.ChildCount()); i++ {
		child := funcNode.Child(i)
		if child != nil && child.Type() == "compound_statement" {
			return child
		}
	}
	return nil
}

// analyzeFunctionBody 分析函数体
func (fsm *FunctionSummaryManager) analyzeFunctionBody(body *sitter.Node, summary *FunctionSummary) {
	// 递归分析函数体中的所有语句
	fsm.analyzeStatement(body, summary)
}

// analyzeStatement 分析语句
func (fsm *FunctionSummaryManager) analyzeStatement(stmt *sitter.Node, summary *FunctionSummary) {
	if stmt == nil {
		return
	}

	stmtType := stmt.Type()

	// 赋值语句：检查是否赋值给指针参数
	if stmtType == "assignment_expression" ||
	   (stmtType == "expression_statement" && stmt.ChildCount() > 0 &&
	    stmt.Child(0).Type() == "assignment_expression") {
		fsm.analyzeAssignment(stmt, summary)
	}

	// 函数调用：递归分析
	if stmtType == "call_expression" ||
	   (stmtType == "expression_statement" && stmt.ChildCount() > 0 &&
	    stmt.Child(0).Type() == "call_expression") {
		var callNode *sitter.Node
		if stmtType == "call_expression" {
			callNode = stmt
		} else {
			callNode = stmt.Child(0)
		}
		fsm.analyzeFunctionCall(callNode, summary)
	}

	// 递归分析子语句
	for i := 0; i < int(stmt.ChildCount()); i++ {
		child := stmt.Child(i)
		if child != nil {
			fsm.analyzeStatement(child, summary)
		}
	}
}

// analyzeAssignment 分析赋值语句
func (fsm *FunctionSummaryManager) analyzeAssignment(stmt *sitter.Node, summary *FunctionSummary) {
	var assignNode *sitter.Node
	if stmt.Type() == "assignment_expression" {
		assignNode = stmt
	} else if stmt.ChildCount() > 0 {
		assignNode = stmt.Child(0)
	}

	if assignNode == nil {
		return
	}

	// 检查左值
	left := assignNode.Child(0)
	if left == nil {
		return
	}

	// 如果是解引用操作: *param = value
	if left.Type() == "dereference_expression" ||
	   left.Type() == "pointer_indirection_expression" {
		operand := left.Child(0)
		if operand != nil && operand.Type() == "identifier" {
			// 这是一个通过参数指针写入的操作
			summary.HasSideEffects = true
		}
	}
}

// analyzeFunctionCall 分析函数调用
func (fsm *FunctionSummaryManager) analyzeFunctionCall(callNode *sitter.Node, summary *FunctionSummary) {
	if callNode == nil {
		return
	}

	// 获取被调用函数名
	funcNode := callNode.Child(0)
	if funcNode == nil {
		return
	}

	calledFuncName := fsm.ctx.GetSourceText(funcNode)

	// 如果被调用函数有副作用，当前函数也有副作用
	if calledSummary, ok := fsm.summaries[calledFuncName]; ok {
		if calledSummary.HasSideEffects {
			summary.HasSideEffects = true
		}
	}

	// 检查是否传递了指针参数
	for i := 1; i < int(callNode.ChildCount()); i++ {
		arg := callNode.Child(i)
		if arg != nil && arg.Type() == "argument" && arg.ChildCount() > 0 {
			expr := arg.Child(0)
			if expr != nil && (expr.Type() == "address_of_expression" ||
			                   expr.Type() == "identifier") {
				// 传递了可能被修改的参数
				summary.HasSideEffects = true
			}
		}
	}
}

// applyKnownFunctionSummary 应用已知函数的预定义摘要
func (fsm *FunctionSummaryManager) applyKnownFunctionSummary(summary *FunctionSummary) {
	// C标准库函数的输出参数
	knownOutputs := map[string]map[int]bool{
		// 输入函数
		"scanf":       {1: true, 2: true, 3: true, 4: true},
		"fscanf":      {2: true, 3: true, 4: true},
		"sscanf":      {2: true, 3: true, 4: true},
		"fgets":       {0: true},
		"gets":        {0: true},
		"fread":       {0: true},
		"read":        {1: true, 2: true},

		// 字符串函数
		"strcpy":      {0: true},
		"strncpy":     {0: true},
		"strcat":      {0: true},
		"strncat":     {0: true},
		"sprintf":     {0: true},
		"snprintf":    {0: true},
		"memcpy":      {0: true},
		"memmove":     {0: true},
		"memset":      {0: true},

		// 时间函数
		"gmtime":      {0: true},
		"localtime":   {0: true},
		"ctime":       {0: true},
		"asctime":     {0: true},

		// 网络函数
		"gethostbyname":  {0: true},
		"gethostbyaddr":  {0: true},
		"gethostbyname2": {0: true},
		"getnetbyname":   {0: true},
		"getnetbyaddr":   {0: true},
		"getprotobyname": {0: true},
		"getservbyname":  {0: true},
		"getservbyport":  {0: true},

		// 线程函数
		"pthread_create":  {3: true},

		// OpenSSL通用函数（启发式）
		// *2* 模式（如 ossl_asn1_time_to_tm）
	}

	if outputs, ok := knownOutputs[summary.FuncName]; ok {
		for paramIdx := range outputs {
			summary.OutputParams[paramIdx] = true
		}
		summary.HasSideEffects = true
	}

	// 启发式：函数名包含特定关键字
	funcName := summary.FuncName
	lowerName := funcName

	// _to_ 模式：第一个或第二个参数通常是输出
	if contains(lowerName, "_to_") || contains(lowerName, "To") {
		if len(summary.OutputParams) == 0 {
			summary.OutputParams[0] = true
			summary.OutputParams[1] = true
		}
		summary.HasSideEffects = true
	}

	// _load, _store, _read, _write 模式
	loadStoreKeywords := []string{"load", "store", "read", "write", "fetch", "get"}
	for _, kw := range loadStoreKeywords {
		if contains(lowerName, kw) {
			summary.OutputParams[0] = true
			summary.HasSideEffects = true
			break
		}
	}

	// init, setup, create 模式
	initKeywords := []string{"init", "setup", "create", "alloc"}
	for _, kw := range initKeywords {
		if contains(lowerName, kw) {
			summary.HasSideEffects = true
			break
		}
	}
}

// GetSummary 获取函数摘要
func (fsm *FunctionSummaryManager) GetSummary(funcName string) *FunctionSummary {
	return fsm.summaries[funcName]
}

// IsOutputParameter 检查函数的参数是否是输出参数
func (fsm *FunctionSummaryManager) IsOutputParameter(funcName string, paramIndex int) bool {
	summary := fsm.GetSummary(funcName)
	if summary == nil {
		return false
	}
	return summary.OutputParams[paramIndex]
}

// extractFunctionName 从函数定义节点中提取函数名
func (fsm *FunctionSummaryManager) extractFunctionName(funcNode *sitter.Node) string {
	for i := 0; i < int(funcNode.ChildCount()); i++ {
		child := funcNode.Child(i)
		if child == nil {
			continue
		}

		childType := child.Type()

		// function_declarator
		if childType == "function_declarator" {
			return fsm.extractNameFromDeclarator(child)
		}

		// 直接的identifier（某些情况下）
		if childType == "identifier" && i > 0 {
			return fsm.ctx.GetSourceText(child)
		}
	}
	return ""
}

// extractNameFromDeclarator 从declarator中提取函数名
func (fsm *FunctionSummaryManager) extractNameFromDeclarator(decl *sitter.Node) string {
	for i := 0; i < int(decl.ChildCount()); i++ {
		child := decl.Child(i)
		if child == nil {
			continue
		}

		if child.Type() == "identifier" {
			return fsm.ctx.GetSourceText(child)
		}

		// pointer_declarator 或 declarator
		if child.Type() == "pointer_declarator" ||
		   child.Type() == "declarator" {
			return fsm.extractNameFromDeclarator(child)
		}
	}
	return ""
}

// 辅助函数
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		findInString(s, substr))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func splitBy2(s string) []string {
	for i := 1; i < len(s)-1; i++ {
		if s[i] == '2' && s[i-1] != '2' && s[i+1] != '2' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return nil
}
