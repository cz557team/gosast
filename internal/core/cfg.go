package core

import (
	"fmt"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
)

// BlockType 表示基本块的类型
type BlockType int

const (
	BlockEntry BlockType = iota
	BlockExit
	BlockStatement
	BlockCondition
	BlockBranch
	BlockLoop
)

// CFGNode 表示控制流图中的一个节点
type CFGNode struct {
	ID           int
	Type         BlockType
	ASTNode      *sitter.Node
	Predecessors []*CFGNode
	Successors   []*CFGNode
	Statements   []*sitter.Node
	Condition    *sitter.Node // 条件节点存储条件表达式
	// 用于辅助分析的属性
	Visited      bool
	Dominator    *CFGNode
	DomTreeDepth int
}

// CFG 表示完整的控制流图
type CFG struct {
	Entry   *CFGNode
	Exit    *CFGNode
	Nodes   []*CFGNode
	Edges   [][2]int // 存储边的源和目标节点ID
	nodeMap map[uintptr]*CFGNode // AST节点ID到CFG节点的映射
	mu      sync.RWMutex          // 保护 nodeMap 的并发访问
}

// cfgBuilder 用于构建CFG的辅助结构
type cfgBuilder struct {
	cfg         *CFG
	currentFunc *CFGNode
	nodeCounter int
}

// NewCFG 创建新的控制流图
func NewCFG() *CFG {
	return &CFG{
		Nodes:   make([]*CFGNode, 0),
		Edges:   make([][2]int, 0),
		nodeMap: make(map[uintptr]*CFGNode),
	}
}

// BuildCFG 为给定的解析单元构建控制流图
func BuildCFG(unit *ParsedUnit) (*CFG, error) {
	builder := &cfgBuilder{
		cfg:         NewCFG(),
		nodeCounter: 0,
	}

	// 查找所有函数定义
	funcMatches, err := NewAnalysisContext(unit).FindFunctionDeclarations()
	if err != nil {
		return nil, fmt.Errorf("failed to find function declarations: %w", err)
	}

	// 为每个函数构建CFG
	for _, match := range funcMatches {
		if bodyNode, ok := match.Captures["body"]; ok {
			err := builder.buildFunctionCFG(bodyNode)
			if err != nil {
				return nil, fmt.Errorf("failed to build CFG for function: %w", err)
			}
		}
	}

	return builder.cfg, nil
}

// buildFunctionCFG 为单个函数构建CFG
func (b *cfgBuilder) buildFunctionCFG(funcNode *sitter.Node) error {
	// 创建函数入口节点
	entry := b.createNode(BlockEntry, funcNode)
	b.cfg.Entry = entry

	// 创建函数退出节点
	exit := b.createNode(BlockExit, nil)
	b.cfg.Exit = exit

	// 递归构建CFG
	b.currentFunc = entry
	b.buildNodeCFG(funcNode, entry)
	b.connectToExit(exit)

	
	return nil
}

// createNode 创建新的CFG节点
func (b *cfgBuilder) createNode(nodeType BlockType, astNode *sitter.Node) *CFGNode {
	node := &CFGNode{
		ID:          b.nodeCounter,
		Type:        nodeType,
		ASTNode:     astNode,
		Statements:  make([]*sitter.Node, 0),
		Predecessors: make([]*CFGNode, 0),
		Successors:   make([]*CFGNode, 0),
	}

	b.cfg.Nodes = append(b.cfg.Nodes, node)
	b.nodeCounter++

	if astNode != nil {
		b.cfg.mu.Lock()
		b.cfg.nodeMap[astNode.ID()] = node
		b.cfg.mu.Unlock()
	}

	return node
}

// buildNodeCFG 递归构建节点的CFG
func (b *cfgBuilder) buildNodeCFG(node *sitter.Node, entry *CFGNode) *CFGNode {
	switch node.Type() {
	case "compound_statement":
		return b.buildCompoundStatement(node, entry)

	case "if_statement":
		return b.buildIfStatement(node, entry)

	case "for_statement", "while_statement", "do_statement":
		return b.buildLoopStatement(node, entry)

	case "switch_statement":
		return b.buildSwitchStatement(node, entry)

	case "return_statement", "break_statement", "continue_statement", "goto_statement":
		return b.buildControlTransfer(node, entry)

	case "call_expression":
		// 函数调用，检查是否是exit相关的函数
		return b.buildStatement(node, entry)

	default:
		// 普通语句
		if isStatement(node) {
			return b.buildStatement(node, entry)
		}

		// 递归处理子节点
		var lastNode *CFGNode = entry
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil {
				lastNode = b.buildNodeCFG(child, lastNode)
			}
		}
		return lastNode
	}
}

// buildCompoundStatement 构建复合语句的CFG
func (b *cfgBuilder) buildCompoundStatement(node *sitter.Node, entry *CFGNode) *CFGNode {
	lastNode := entry

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && isStatement(child) {
			lastNode = b.buildNodeCFG(child, lastNode)
		}
	}

	return lastNode
}

// buildIfStatement 构建if语句的CFG
func (b *cfgBuilder) buildIfStatement(node *sitter.Node, entry *CFGNode) *CFGNode {
	// 创建条件节点
	conditionNode := node.ChildByFieldName("condition")
	condition := b.createNode(BlockCondition, conditionNode)
	condition.Condition = conditionNode
	b.addEdge(entry, condition)

	// 处理consequence分支
	consequenceNode := node.ChildByFieldName("consequence")
	consequenceEntry := b.createNode(BlockBranch, consequenceNode)
	b.addEdge(condition, consequenceEntry)
	consequenceExit := b.buildNodeCFG(consequenceNode, consequenceEntry)

	// 处理alternative分支（else部分）
	var alternativeExit *CFGNode
	if alternativeNode := node.ChildByFieldName("alternative"); alternativeNode != nil {
		alternativeEntry := b.createNode(BlockBranch, alternativeNode)
		b.addEdge(condition, alternativeEntry)
		alternativeExit = b.buildNodeCFG(alternativeNode, alternativeEntry)

		// 创建汇聚点
		mergeNode := b.createNode(BlockStatement, nil)
		if consequenceExit != nil {
			b.addEdge(consequenceExit, mergeNode)
		}
		if alternativeExit != nil {
			b.addEdge(alternativeExit, mergeNode)
		}
		return mergeNode
	} else {
		// 没有else分支，if结束点就是汇聚点
		mergeNode := b.createNode(BlockStatement, nil)
		if consequenceExit != nil {
			b.addEdge(consequenceExit, mergeNode)
		}
		b.addEdge(condition, mergeNode) // 条件为false时跳过if
		return mergeNode
	}
}

// buildLoopStatement 构建循环语句的CFG
func (b *cfgBuilder) buildLoopStatement(node *sitter.Node, entry *CFGNode) *CFGNode {
	// 创建循环头节点
	loopHeader := b.createNode(BlockLoop, node)
	b.addEdge(entry, loopHeader)

	// 创建条件节点
	var condition *CFGNode
	if conditionNode := node.ChildByFieldName("condition"); conditionNode != nil {
		condition = b.createNode(BlockCondition, conditionNode)
		condition.Condition = conditionNode
		b.addEdge(loopHeader, condition)
	} else {
		condition = loopHeader
	}

	// 处理循环体
	var bodyExit *CFGNode
	if bodyNode := node.ChildByFieldName("body"); bodyNode != nil {
		bodyEntry := b.createNode(BlockBranch, bodyNode)
		b.addEdge(condition, bodyEntry)
		bodyExit = b.buildNodeCFG(bodyNode, bodyEntry)

		// 循环体完成后回到循环头
		if bodyExit != nil {
			b.addEdge(bodyExit, loopHeader)
		}
	}

	// 创建循环出口节点
	loopExit := b.createNode(BlockStatement, nil)
	b.addEdge(condition, loopExit) // 条件为false时退出循环

	return loopExit
}

// buildSwitchStatement 构建switch语句的CFG
func (b *cfgBuilder) buildSwitchStatement(node *sitter.Node, entry *CFGNode) *CFGNode {
	// 创建switch头节点
	switchHeader := b.createNode(BlockCondition, node)
	b.addEdge(entry, switchHeader)

	// 处理各个case
	var lastCaseExit *CFGNode
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && (child.Type() == "case_statement" || child.Type() == "default_statement") {
			caseNode := b.createNode(BlockBranch, child)
			b.addEdge(switchHeader, caseNode)
			caseExit := b.buildNodeCFG(child, caseNode)

			if lastCaseExit != nil && caseExit != nil {
				// 连接前一个case的出口到当前case（除非有break）
				b.addEdge(lastCaseExit, caseNode)
			}
			lastCaseExit = caseExit
		}
	}

	// 创建switch出口
	switchExit := b.createNode(BlockStatement, nil)
	if lastCaseExit != nil {
		b.addEdge(lastCaseExit, switchExit)
	}
	b.addEdge(switchHeader, switchExit) // 默认情况

	return switchExit
}

// buildControlTransfer 构建控制转移语句的CFG
func (b *cfgBuilder) buildControlTransfer(node *sitter.Node, entry *CFGNode) *CFGNode {
	stmtNode := b.createNode(BlockStatement, node)
	b.addEdge(entry, stmtNode)

	// 返回语句直接连接到函数退出节点
	if node.Type() == "return_statement" {
		b.addEdge(stmtNode, b.cfg.Exit)
	}

	return stmtNode
}

// buildStatement 构建普通语句的CFG
func (b *cfgBuilder) buildStatement(node *sitter.Node, entry *CFGNode) *CFGNode {
	stmtNode := b.createNode(BlockStatement, node)
	stmtNode.Statements = append(stmtNode.Statements, node)
	b.addEdge(entry, stmtNode)
	return stmtNode
}

// connectToExit 确保所有未连接的节点都连接到exit
func (b *cfgBuilder) connectToExit(exit *CFGNode) {
	for _, node := range b.cfg.Nodes {
		if node != exit && len(node.Successors) == 0 && node.Type != BlockExit {
			b.addEdge(node, exit)
		}
	}
}

// addEdge 添加CFG边
func (b *cfgBuilder) addEdge(from, to *CFGNode) {
	from.Successors = append(from.Successors, to)
	to.Predecessors = append(to.Predecessors, from)
	b.cfg.Edges = append(b.cfg.Edges, [2]int{from.ID, to.ID})
}

// isStatement 判断节点是否是语句
func isStatement(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	switch node.Type() {
	case "expression_statement", "declaration", "compound_statement",
		 "return_statement", "break_statement", "continue_statement",
		 "goto_statement", "call_expression", "assignment_expression",
		 "if_statement", "for_statement", "while_statement", "do_statement",
		 "switch_statement", "case_statement", "default_statement":
		return true
	default:
		return false
	}
}

// GetNodeByAST 根据AST节点查找对应的CFG节点
func (cfg *CFG) GetNodeByAST(astNode *sitter.Node) *CFGNode {
	if astNode == nil {
		return nil
	}
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	return cfg.nodeMap[astNode.ID()]
}

// GetReachableNodes 获取从给定节点可达的所有节点
func (cfg *CFG) GetReachableNodes(start *CFGNode) []*CFGNode {
	visited := make(map[int]bool)
	worklist := []*CFGNode{start}
	var reachable []*CFGNode

	for len(worklist) > 0 {
		current := worklist[0]
		worklist = worklist[1:]

		if visited[current.ID] {
			continue
		}

		visited[current.ID] = true
		reachable = append(reachable, current)

		for _, successor := range current.Successors {
			if !visited[successor.ID] {
				worklist = append(worklist, successor)
			}
		}
	}

	return reachable
}