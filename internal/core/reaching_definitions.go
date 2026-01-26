package core

import (
	"fmt"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
)

// Definition 表示变量的一个定义点
type Definition struct {
	VarName    string         // 变量名
	Node       *sitter.Node   // 定义节点（声明或赋值）
	IsInit     bool           // 是否是初始化（声明时赋值）
	LineNumber int            // 行号
	DefID      string         // 唯一标识符
}

// ReachingDefinitions 到达定义分析结果
// 对于每个程序点，记录哪些定义可能到达该点
type ReachingDefinitions struct {
	// CFG节点的ID -> 到达该节点的定义集合
	In map[int][]*Definition  // 进入基本块时的定义
	Out map[int][]*Definition // 离开基本块时的定义

	// 生成和杀死的定义集合
	Gen map[int][]*Definition // 基本块生成的定义
	Kill map[int]map[string]bool // 基本块杀死的定义（变量名 -> true）

	// 变量到定义的映射
	VarDefs map[string][]*Definition

	cfg *CFG
	ctx *AnalysisContext

	// 【迭代22新增】函数摘要（过程间分析）
	funcSummary *FunctionSummaryManager

	mu  sync.RWMutex
}

// NewReachingDefinitions 创建新的到达定义分析
func NewReachingDefinitions(cfg *CFG, ctx *AnalysisContext) *ReachingDefinitions {
	return &ReachingDefinitions{
		In:      make(map[int][]*Definition),
		Out:     make(map[int][]*Definition),
		Gen:     make(map[int][]*Definition),
		Kill:    make(map[int]map[string]bool),
		VarDefs: make(map[string][]*Definition),
		cfg:     cfg,
		ctx:     ctx,
	}
}

// 【迭代22新增】SetFunctionSummary 设置函数摘要管理器
func (rd *ReachingDefinitions) SetFunctionSummary(fs *FunctionSummaryManager) {
	rd.funcSummary = fs
}

// Analyze 执行到达定义分析（数据流方程的迭代求解）
func (rd *ReachingDefinitions) Analyze() error {
	if rd.cfg == nil || rd.cfg.Entry == nil {
		return fmt.Errorf("CFG not built or empty")
	}

	// 第1步：计算每个基本块的Gen和Kill集合
	rd.computeGenKill()

	// 第2步：初始化（Entry节点没有输入）
	for _, node := range rd.cfg.Nodes {
		rd.In[node.ID] = make([]*Definition, 0)
		rd.Out[node.ID] = make([]*Definition, 0)
	}

	// 第3步：Worklist算法求解数据流方程
	worklist := make([]*CFGNode, 0)
	visited := make(map[int]bool)

	// 从所有节点开始
	for _, node := range rd.cfg.Nodes {
		worklist = append(worklist, node)
	}

	iterations := 0
	maxIterations := 10000 // 防止无限循环

	for len(worklist) > 0 && iterations < maxIterations {
		iterations++

		// 从worklist中取出一个节点
		node := worklist[0]
		worklist = worklist[1:]

		// 计算新的In集合：所有前驱的Out集合并集
		oldIn := rd.copyDefs(rd.In[node.ID])
		rd.In[node.ID] = rd.mergePredecessorOuts(node)

		// 计算新的Out集合：(In - Kill) ∪ Gen
		oldOut := rd.copyDefs(rd.Out[node.ID])
		rd.Out[node.ID] = rd.computeOut(node)

		// 如果In或Out发生变化，将后继加入worklist
		if !rd.defsEqual(oldIn, rd.In[node.ID]) ||
		   !rd.defsEqual(oldOut, rd.Out[node.ID]) {
			for _, succ := range node.Successors {
				if !visited[succ.ID] {
					worklist = append(worklist, succ)
				}
			}
			visited[node.ID] = false // 允许重新访问
		}
	}

	if iterations >= maxIterations {
		return fmt.Errorf("reaching definitions analysis failed to converge")
	}

	return nil
}

// computeGenKill 计算每个基本块的Gen和Kill集合
func (rd *ReachingDefinitions) computeGenKill() {
	for _, node := range rd.cfg.Nodes {
		rd.Gen[node.ID] = make([]*Definition, 0)
		rd.Kill[node.ID] = make(map[string]bool)

		// 遍历基本块中的所有语句
		for _, stmt := range node.Statements {
			rd.processStatement(node, stmt)
		}
	}
}

// processStatement 处理单个语句，更新Gen和Kill
func (rd *ReachingDefinitions) processStatement(block *CFGNode, stmt *sitter.Node) {
	stmtType := stmt.Type()

	// 处理变量声明
	if stmtType == "declaration" {
		rd.processDeclaration(block, stmt)
		return
	}

	// 处理赋值表达式
	if stmtType == "assignment_expression" ||
	   (stmtType == "expression_statement" &&
	    stmt.ChildCount() > 0 &&
	    stmt.Child(0).Type() == "assignment_expression") {
		rd.processAssignment(block, stmt)
		return
	}

	// 处理函数调用（可能通过指针参数写入变量）
	if stmtType == "call_expression" ||
	   (stmtType == "expression_statement" &&
	    stmt.ChildCount() > 0 &&
	    stmt.Child(0).Type() == "call_expression") {
		rd.processCall(block, stmt)
	}
}

// processDeclaration 处理变量声明
func (rd *ReachingDefinitions) processDeclaration(block *CFGNode, decl *sitter.Node) {
	// 提取变量名
	varName := rd.extractVariableName(decl)
	if varName == "" {
		return
	}

	// 创建定义
	def := &Definition{
		VarName:    varName,
		Node:       decl,
		IsInit:     rd.isInitializedDeclaration(decl),
		LineNumber: int(decl.StartPoint().Row) + 1,
		DefID:      fmt.Sprintf("%s_%d", varName, decl.StartByte()),
	}

	// 添加到Gen
	rd.Gen[block.ID] = append(rd.Gen[block.ID], def)

	// 记录变量的所有定义
	rd.VarDefs[varName] = append(rd.VarDefs[varName], def)

	// 这个新定义杀死了该变量的所有旧定义
	if rd.Kill[block.ID] == nil {
		rd.Kill[block.ID] = make(map[string]bool)
	}
	rd.Kill[block.ID][varName] = true
}

// processAssignment 处理赋值语句
func (rd *ReachingDefinitions) processAssignment(block *CFGNode, stmt *sitter.Node) {
	var assignNode *sitter.Node
	if stmt.Type() == "assignment_expression" {
		assignNode = stmt
	} else {
		assignNode = stmt.Child(0)
	}
	if assignNode == nil {
		return
	}

	// 提取左值
	left := assignNode.Child(0)
	if left == nil {
		return
	}

	varName := ""
	if left.Type() == "identifier" {
		varName = rd.ctx.GetSourceText(left)
	} else if left.Type() == "field_expression" {
		// obj.field = value
		obj := left.Child(0)
		if obj != nil && obj.Type() == "identifier" {
			varName = rd.ctx.GetSourceText(obj)
		}
	} else if left.Type() == "subscript_expression" {
		// array[i] = value
		array := left.Child(0)
		if array != nil && array.Type() == "identifier" {
			varName = rd.ctx.GetSourceText(array)
		}
	}

	if varName == "" {
		return
	}

	// 创建定义
	def := &Definition{
		VarName:    varName,
		Node:       assignNode,
		IsInit:     true, // 赋值语句是初始化
		LineNumber: int(assignNode.StartPoint().Row) + 1,
		DefID:      fmt.Sprintf("%s_assign_%d", varName, assignNode.StartByte()),
	}

	// 添加到Gen
	rd.Gen[block.ID] = append(rd.Gen[block.ID], def)

	// 记录定义
	rd.VarDefs[varName] = append(rd.VarDefs[varName], def)

	// 杀死旧定义
	if rd.Kill[block.ID] == nil {
		rd.Kill[block.ID] = make(map[string]bool)
	}
	rd.Kill[block.ID][varName] = true
}

// processCall 处理函数调用（可能通过指针参数写入）
func (rd *ReachingDefinitions) processCall(block *CFGNode, stmt *sitter.Node) {
	var callNode *sitter.Node
	if stmt.Type() == "call_expression" {
		callNode = stmt
	} else if stmt.ChildCount() > 0 {
		callNode = stmt.Child(0)
	}
	if callNode == nil {
		return
	}

	// 获取函数名
	funcNode := callNode.Child(0)
	if funcNode == nil {
		return
	}
	funcName := rd.ctx.GetSourceText(funcNode)

	// 检查参数中的取地址表达式
	for i := 1; i < int(callNode.ChildCount()); i++ {
		arg := callNode.Child(i)
		if arg == nil || arg.Type() != "argument" {
			continue
		}

		// 检查是否是 &var
		if arg.ChildCount() > 0 {
			expr := arg.Child(0)
			if expr != nil && expr.Type() == "address_of_expression" {
				operand := expr.Child(0)
				if operand != nil && operand.Type() == "identifier" {
					varName := rd.ctx.GetSourceText(operand)

					// 检查是否是已知的输出参数
					if rd.isOutputParameter(funcName, i-1) {
						def := &Definition{
							VarName:    varName,
							Node:       callNode,
							IsInit:     true,
							LineNumber: int(callNode.StartPoint().Row) + 1,
							DefID:      fmt.Sprintf("%s_%s_out_%d", varName, funcName, callNode.StartByte()),
						}

						rd.Gen[block.ID] = append(rd.Gen[block.ID], def)
						rd.VarDefs[varName] = append(rd.VarDefs[varName], def)

						if rd.Kill[block.ID] == nil {
							rd.Kill[block.ID] = make(map[string]bool)
						}
						rd.Kill[block.ID][varName] = true
					}
				}
			}
		}
	}
}

// extractVariableName 从声明中提取变量名
func (rd *ReachingDefinitions) extractVariableName(decl *sitter.Node) string {
	// 查找declarator
	for i := 0; i < int(decl.ChildCount()); i++ {
		child := decl.Child(i)
		if child == nil {
			continue
		}

		childType := child.Type()

		// 直接的identifier
		if childType == "identifier" && i > 0 {
			return rd.ctx.GetSourceText(child)
		}

		// declarator节点
		if childType == "init_declarator" {
			// init_declarator的第一个子节点通常是declarator或identifier
			if child.ChildCount() > 0 {
				firstChild := child.Child(0)
				if firstChild.Type() == "identifier" {
					return rd.ctx.GetSourceText(firstChild)
				} else if firstChild.Type() == "declarator" ||
					   firstChild.Type() == "pointer_declarator" ||
					   firstChild.Type() == "array_declarator" {
					// 递归查找declarator中的identifier
					return rd.findIdentifierInDeclarator(firstChild)
				}
			}
		}

		// 直接的declarator
		if childType == "declarator" ||
		   childType == "pointer_declarator" ||
		   childType == "array_declarator" {
			return rd.findIdentifierInDeclarator(child)
		}
	}

	return ""
}

// findIdentifierInDeclarator 在declarator节点中查找identifier
func (rd *ReachingDefinitions) findIdentifierInDeclarator(decl *sitter.Node) string {
	for i := 0; i < int(decl.ChildCount()); i++ {
		child := decl.Child(i)
		if child == nil {
			continue
		}

		if child.Type() == "identifier" {
			return rd.ctx.GetSourceText(child)
		}

		// 递归搜索嵌套的declarator
		if child.Type() == "declarator" ||
		   child.Type() == "pointer_declarator" {
			if name := rd.findIdentifierInDeclarator(child); name != "" {
				return name
			}
		}
	}

	return ""
}

// isInitializedDeclaration 检查声明是否初始化了变量
func (rd *ReachingDefinitions) isInitializedDeclaration(decl *sitter.Node) bool {
	// 检查是否有init_declarator且包含赋值
	for i := 0; i < int(decl.ChildCount()); i++ {
		child := decl.Child(i)
		if child != nil && child.Type() == "init_declarator" {
			// init_declarator格式: declarator = value
			// 检查是否有"="号
			for j := 0; j < int(child.ChildCount()); j++ {
				if child.Child(j) != nil && child.Child(j).Type() == "=" {
					return true
				}
			}
		}
	}
	return false
}

// isOutputParameter 检查函数的参数是否是输出参数
func (rd *ReachingDefinitions) isOutputParameter(funcName string, paramIndex int) bool {
	// 【迭代22新增】首先检查函数摘要
	if rd.funcSummary != nil {
		if rd.funcSummary.IsOutputParameter(funcName, paramIndex) {
			return true
		}
	}

	// C标准库已知输出参数（后备）
	outputParams := map[string]map[int]bool{
		"scanf":       {1: true, 2: true, 3: true, 4: true},
		"fscanf":      {2: true, 3: true, 4: true},
		"sscanf":      {2: true, 3: true, 4: true},
		"fgets":       {0: true},
		"fread":       {0: true},
		"strcpy":      {0: true},
		"strncpy":     {0: true},
		"sprintf":     {0: true},
		"snprintf":    {0: true},
		"strcmp":      {0: true},
		"strncmp":     {0: true},
		"strcat":      {0: true},
		"strncat":     {0: true},
		"memcpy":      {0: true},
		"memmove":     {0: true},
		"memset":      {0: true},
		"gmtime":      {0: true},
		"localtime":   {0: true},
		"asctime":     {0: true},
		"ctime":       {0: true},
		"gethostbyname": {0: true},
		"gethostbyaddr": {0: true},
		"gethostbyname2": {0: true},
		"getnetbyname": {0: true},
		"getnetbyaddr": {0: true},
		"getprotobyname": {0: true},
		"getprotobynumber": {0: true},
		"getservbyname": {0: true},
		"getservbyport": {0: true},
	}

	if params, ok := outputParams[funcName]; ok {
		return params[paramIndex]
	}

	// C语言通用启发式规则
	lowerName := funcName

	// X2Y转换模式
	if contains(lowerName, "2") {
		parts := splitBy2(lowerName)
		if len(parts) == 2 {
			// 第二个参数通常是输出
			if paramIndex == 1 {
				return true
			}
		}
	}

	// _to_ 模式
	if contains(lowerName, "_to_") || contains(lowerName, "To") {
		if paramIndex == 0 || paramIndex == 1 {
			return true
		}
	}

	// 常见输出参数关键字
	outputKeywords := []string{"load", "store", "read", "write", "fetch", "get", "copy", "move"}
	for _, kw := range outputKeywords {
		if contains(lowerName, kw) {
			// 第一个参数通常是输出
			if paramIndex == 0 {
				return true
			}
		}
	}

	return false
}

// mergePredecessorOuts 合并所有前驱的Out集合
func (rd *ReachingDefinitions) mergePredecessorOuts(node *CFGNode) []*Definition {
	result := make([]*Definition, 0)
	seen := make(map[string]bool)

	for _, pred := range node.Predecessors {
		for _, def := range rd.Out[pred.ID] {
			if !seen[def.DefID] {
				seen[def.DefID] = true
				result = append(result, def)
			}
		}
	}

	return result
}

// computeOut 计算 (In - Kill) ∪ Gen
func (rd *ReachingDefinitions) computeOut(node *CFGNode) []*Definition {
	// In - Kill
	result := make([]*Definition, 0)
	for _, def := range rd.In[node.ID] {
		if !rd.Kill[node.ID][def.VarName] {
			result = append(result, def)
		}
	}

	// ∪ Gen
	seen := make(map[string]bool)
	for _, def := range result {
		seen[def.DefID] = true
	}

	for _, def := range rd.Gen[node.ID] {
		if !seen[def.DefID] {
			result = append(result, def)
		}
	}

	return result
}

// copyDefs 深拷贝定义列表
func (rd *ReachingDefinitions) copyDefs(defs []*Definition) []*Definition {
	result := make([]*Definition, len(defs))
	copy(result, defs)
	return result
}

// defsEqual 比较两个定义列表是否相等
func (rd *ReachingDefinitions) defsEqual(a, b []*Definition) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[string]bool)
	for _, def := range a {
		aMap[def.DefID] = true
	}

	bMap := make(map[string]bool)
	for _, def := range b {
		bMap[def.DefID] = true
	}

	for id := range aMap {
		if !bMap[id] {
			return false
		}
	}

	for id := range bMap {
		if !aMap[id] {
			return false
		}
	}

	return true
}

// GetReachingDefinitions 获取到达指定节点的所有定义
func (rd *ReachingDefinitions) GetReachingDefinitions(node *sitter.Node) []*Definition {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	// 找到包含该节点的CFG基本块
	block := rd.findContainingBlock(node)
	if block == nil {
		return nil
	}

	return rd.In[block.ID]
}

// IsVariableInitializedBeforeUse 检查变量在使用点前是否已初始化
func (rd *ReachingDefinitions) IsVariableInitializedBeforeUse(
	varName string,
	useNode *sitter.Node,
) bool {
	// 获取到达使用点的定义
	reachingDefs := rd.GetReachingDefinitions(useNode)
	if reachingDefs == nil {
		return false
	}

	// 检查是否有该变量的初始化定义
	for _, def := range reachingDefs {
		if def.VarName == varName && def.IsInit {
			return true
		}
	}

	return false
}

// findContainingBlock 查找包含AST节点的CFG基本块
func (rd *ReachingDefinitions) findContainingBlock(node *sitter.Node) *CFGNode {
	if rd.cfg == nil {
		return nil
	}

	nodeStart := node.StartByte()
	nodeEnd := node.EndByte()

	for _, block := range rd.cfg.Nodes {
		// 检查block的任意语句是否包含该节点
		for _, stmt := range block.Statements {
			stmtStart := stmt.StartByte()
			stmtEnd := stmt.EndByte()

			if nodeStart >= stmtStart && nodeEnd <= stmtEnd {
				return block
			}
		}
	}

	return nil
}
