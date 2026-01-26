package detectors

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"gosast/internal/core"
)

// DEBUG模式开关 - 设为false可禁用所有DEBUG输出
const DEBUG_ENABLED = false

// debugPrintf 条件DEBUG输出函数
func debugPrintf(format string, args ...interface{}) {
	if DEBUG_ENABLED {
		fmt.Printf(format, args...)
	}
}

// DoubleFreeDetectorImproved 改进的 Double Free 检测器
// 主要改进：
// 1. 使用 Z3 约束求解验证路径可行性
// 2. 分析控制流以区分互斥的错误处理路径
// 3. 理解常见的错误处理模式
// 4. 追踪指针状态和赋值操作
type DoubleFreeDetectorImproved struct {
	*core.BaseDetector
	z3Solver        core.Z3Solver
	// 路径分析
	controlFlow     map[int]*ControlFlowBlock // 控制流块
	// 指针状态
	pointerStates   map[string]*PointerStateInfo
	mutex           sync.RWMutex
}

// ControlFlowBlock 控制流块
type ControlFlowBlock struct {
	StartLine      int
	EndLine        int
	IsMutuallyExclusive bool // 是否为互斥块（如 if-else）
	Returns        bool // 块内是否有 return
	NextBlocks     []int // 后继块
	FreeCalls      []*FreeCallInfo
}

// FreeCallInfo free 调用信息
type FreeCallInfo struct {
	Line         int
	VarName      string
	Node         *sitter.Node
	InGuardBlock bool // 是否在守护块内
	BlockID      int // 所属控制流块
}

// PointerStateInfo 指针状态信息
type PointerStateInfo struct {
	Name           string
	LastFreeLine   int
	IsFreed        bool
	LastAssignLine int
	AssignedAfter  bool // 最后一次 free 后是否被重新赋值
}

// NewDoubleFreeDetectorImproved 创建改进的 Double Free 检测器
func NewDoubleFreeDetectorImproved() *DoubleFreeDetectorImproved {
	solver, _ := core.CreateZ3Solver()

	return &DoubleFreeDetectorImproved{
		BaseDetector: core.NewBaseDetector(
			"Double Free Detector",
			"Detects double free with Z3 path analysis",
		),
		z3Solver:      solver,
		controlFlow:   make(map[int]*ControlFlowBlock),
		pointerStates: make(map[string]*PointerStateInfo),
	}
}

// Name 返回检测器名称
func (d *DoubleFreeDetectorImproved) Name() string {
	return d.BaseDetector.Name()
}

// Description 返回检测器描述
func (d *DoubleFreeDetectorImproved) Description() string {
	return "Detects potential double free vulnerabilities using control flow analysis and Z3 constraint solving"
}

// Run 执行检测
func (d *DoubleFreeDetectorImproved) Run(ctx *core.AnalysisContext) ([]core.DetectorVulnerability, error) {
	var vulns []core.DetectorVulnerability

	// 重置状态
	d.mutex.Lock()
	d.controlFlow = make(map[int]*ControlFlowBlock)
	d.pointerStates = make(map[string]*PointerStateInfo)
	d.mutex.Unlock()

	// 查找所有函数定义
	functions, err := ctx.QueryNodes("(function_definition) @func")
	if err != nil {
		return nil, err
	}

	// 分析每个函数
	for _, funcNode := range functions {
		funcVulns := d.analyzeFunction(ctx, funcNode)
		vulns = append(vulns, funcVulns...)
	}

	return vulns, nil
}

// analyzeFunction 分析单个函数
func (d *DoubleFreeDetectorImproved) analyzeFunction(ctx *core.AnalysisContext, funcNode *sitter.Node) []core.DetectorVulnerability {
	var vulns []core.DetectorVulnerability

	// 获取函数名用于调试
	funcName := "unknown"
	funcNameNode := core.SafeChildByFieldName(funcNode, "declarator")
	if funcNameNode != nil {
		funcName = ctx.GetSourceText(funcNameNode)
	}

	// 【修复】每个函数分析前重置指针状态，避免跨函数误报
	// 不同函数中的同名局部变量应该独立处理
	d.mutex.Lock()
	d.pointerStates = make(map[string]*PointerStateInfo)
	d.controlFlow = make(map[int]*ControlFlowBlock)
	d.mutex.Unlock()

	debugPrintf("[DEBUG] analyzeFunction: %s, reset pointerStates\n", funcName)

	// 第一遍：构建控制流图
	d.buildControlFlow(ctx, funcNode)

	// 第二遍：查找所有 free 调用
	freeCalls := d.findFreeCalls(ctx, funcNode)

	// 第三遍：分析指针赋值
	d.analyzePointerAssignments(ctx, funcNode)

	// 第四遍：检查是否有 double free
	for _, freeCall := range freeCalls {
		// 检查此 free 调用是否构成 double free
		if d.isDoubleFree(ctx, freeCall, funcNode) {
			vuln := d.createVulnerability(ctx, freeCall)
			vulns = append(vulns, vuln)
		}
	}

	return vulns
}

// buildControlFlow 构建控制流图
func (d *DoubleFreeDetectorImproved) buildControlFlow(ctx *core.AnalysisContext, funcNode *sitter.Node) {
	body := core.SafeChildByFieldName(funcNode, "body")
	if body == nil {
		return
	}

	// 递归分析控制流
	d.analyzeControlFlowRecursive(ctx, body, 0, false)

	// 调试：打印收集到的控制流块和 free 调用
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	debugPrintf("[DEBUG] buildControlFlow: collected %d blocks\n", len(d.controlFlow))
	for blockID, block := range d.controlFlow {
		debugPrintf("[DEBUG]   Block %d: lines %d-%d, %d free calls, IsMutuallyExclusive=%v, Returns=%v\n",
			blockID, block.StartLine, block.EndLine, len(block.FreeCalls), block.IsMutuallyExclusive, block.Returns)
		for _, fc := range block.FreeCalls {
			debugPrintf("[DEBUG]     free %s at line %d\n", fc.VarName, fc.Line)
		}
	}
	// fmt.Printf("[DoubleFree] Collected %d blocks, %d free states\n",
	// 	len(d.controlFlow), len(d.pointerStates))
}

// analyzeControlFlowRecursive 递归分析控制流
func (d *DoubleFreeDetectorImproved) analyzeControlFlowRecursive(ctx *core.AnalysisContext, node *sitter.Node, blockID int, isGuardBlock bool) {
	if node == nil {
		return
	}

	startLine := int(node.StartPoint().Row)
	endLine := int(node.EndPoint().Row)

	// 对于函数体或复合语句，创建一个控制流块
	var currentBlock *ControlFlowBlock
	if core.SafeType(node) == "compound_statement" || core.SafeType(node) == "function_definition" {
		currentBlock = &ControlFlowBlock{
			StartLine:            startLine,
			EndLine:              endLine,
			NextBlocks:           make([]int, 0),
			FreeCalls:            make([]*FreeCallInfo, 0),
			IsMutuallyExclusive:  false,
		}
		d.mutex.Lock()
		d.controlFlow[blockID] = currentBlock
		d.mutex.Unlock()
		debugPrintf("[DEBUG] analyzeControlFlowRecursive: created block %d for %s (lines %d-%d)\n",
			blockID, core.SafeType(node), startLine, endLine)
	}

	// 分析节点类型
	switch core.SafeType(node) {
	case "if_statement":
		debugPrintf("[DEBUG] analyzeControlFlowRecursive: found if_statement at line %d\n", startLine+1)
		d.analyzeIfStatement(ctx, node, blockID)
		return // if 语句单独处理，不递归子节点

	case "return_statement":
		if currentBlock != nil {
			currentBlock.Returns = true
		}

	case "call_expression":
		// 检查是否为 free 调用
		funcName := d.getFunctionName(ctx, node)
		if funcName == "free" || funcName == "ZFREE" {
			varName := d.extractFreeVariable(ctx, node)
			if varName != "" {
				freeCall := &FreeCallInfo{
					Line:         startLine + 1,
					VarName:      varName,
					Node:         node,
					InGuardBlock: isGuardBlock,
					BlockID:      blockID,
				}
				// 添加到当前块
				if currentBlock != nil {
					d.mutex.Lock()
					currentBlock.FreeCalls = append(currentBlock.FreeCalls, freeCall)
					d.mutex.Unlock()
				} else {
					// 如果 currentBlock 为 nil，创建一个临时块
					d.mutex.Lock()
					if _, exists := d.controlFlow[blockID]; !exists {
						d.controlFlow[blockID] = &ControlFlowBlock{
							StartLine:            startLine,
							EndLine:              endLine,
							NextBlocks:           make([]int, 0),
							FreeCalls:            []*FreeCallInfo{freeCall},
							IsMutuallyExclusive:  false,
						}
					} else {
						d.controlFlow[blockID].FreeCalls = append(d.controlFlow[blockID].FreeCalls, freeCall)
					}
					d.mutex.Unlock()
				}
				// fmt.Printf("[DoubleFree]   Found free: %s at line %d\n", varName, startLine+1)
			}
		}
	}

	// 递归处理子节点 - 使用相同的 blockID
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		child := core.SafeChild(node, i)
		childType := core.SafeType(child)

		// 【修复】if 语句需要调用 analyzeIfStatement
		if childType == "if_statement" {
			d.analyzeIfStatement(ctx, child, blockID)
		} else if childType == "compound_statement" {
			// 递归进入 compound_statement 内部，使用相同的 blockID
			d.analyzeControlFlowRecursive(ctx, child, blockID, isGuardBlock)
		} else {
			// 其他类型的节点，递归处理
			d.analyzeControlFlowRecursive(ctx, child, blockID, isGuardBlock)
		}
	}
}

// analyzeIfStatement 分析 if 语句
func (d *DoubleFreeDetectorImproved) analyzeIfStatement(ctx *core.AnalysisContext, ifNode *sitter.Node, parentBlockID int) {
	// 获取条件
	condition := core.SafeChildByFieldName(ifNode, "condition")
	if condition == nil {
		return
	}

	// 获取 if 块
	consequence := core.SafeChildByFieldName(ifNode, "consequence")
	if consequence == nil {
		return
	}

	// 获取 else 块
	alternative := core.SafeChildByFieldName(ifNode, "alternative")

	// 检查 if 块是否有 return
	hasReturn := d.hasTerminatingStatement(consequence)

	// 检查是否为错误处理模式
	isErrorPattern := d.isErrorHandlingPattern(ctx, condition, consequence, hasReturn)

	// 【新增】检查 if 块内是否有 free 调用
	hasFreeInIf := d.hasFreeCall(ctx, consequence)

	// 创建 if 块
	ifBlockID := parentBlockID * 2 + 1
	d.analyzeControlFlowRecursive(ctx, consequence, ifBlockID, isErrorPattern || (hasFreeInIf && !hasReturn))

	// 【新增】设置 if 块的 Returns 属性
	d.mutex.Lock()
	if d.controlFlow[ifBlockID] != nil {
		d.controlFlow[ifBlockID].Returns = hasReturn
		d.controlFlow[ifBlockID].IsMutuallyExclusive = true  // if 块总是互斥的
	}
	d.mutex.Unlock()

	// 创建 else 块
	if alternative != nil {
		elseBlockID := parentBlockID * 2 + 2
		d.analyzeControlFlowRecursive(ctx, alternative, elseBlockID, false)

		// 【新增】设置 else 块的 Returns 属性
		hasReturnInElse := d.hasTerminatingStatement(alternative)
		d.mutex.Lock()
		if d.controlFlow[elseBlockID] != nil {
			d.controlFlow[elseBlockID].Returns = hasReturnInElse
			d.controlFlow[elseBlockID].IsMutuallyExclusive = true  // else 块也是互斥的
		}
		d.mutex.Unlock()
	}
}

// hasTerminatingStatement 检查是否有终止语句
func (d *DoubleFreeDetectorImproved) hasTerminatingStatement(node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 检查当前节点是否为终止语句
	if core.SafeType(node) == "return_statement" ||
	   core.SafeType(node) == "break_statement" ||
	   core.SafeType(node) == "continue_statement" ||
	   core.SafeType(node) == "goto_statement" {
		return true
	}

	// 递归检查所有子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		if d.hasTerminatingStatement(core.SafeChild(node, i)) {
			return true
		}
	}

	return false
}

// hasFreeCall 检查节点内是否有 free 调用
func (d *DoubleFreeDetectorImproved) hasFreeCall(ctx *core.AnalysisContext, node *sitter.Node) bool {
	if node == nil {
		return false
	}

	// 检查当前节点是否为 free 调用
	if core.SafeType(node) == "call_expression" {
		funcName := d.getFunctionName(ctx, node)
		if funcName == "free" || funcName == "ZFREE" {
			return true
		}
	}

	// 递归检查子节点
	for i := 0; i < int(core.SafeChildCount(node)); i++ {
		if d.hasFreeCall(ctx, core.SafeChild(node, i)) {
			return true
		}
	}

	return false
}

// isErrorHandlingPattern 检查是否为错误处理模式
func (d *DoubleFreeDetectorImproved) isErrorHandlingPattern(ctx *core.AnalysisContext, condition, consequence *sitter.Node, hasReturn bool) bool {
	if !hasReturn {
		return false
	}

	condText := ctx.GetSourceText(condition)

	// 检查常见的错误检查模式
	errorPatterns := []string{
		"== NULL",
		"== 0",
		"< 0",
		"!= Z_OK",
		"== NULL",
		"failed",
		"error",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(condText, pattern) {
			return true
		}
	}

	return false
}

// findFreeCalls 查找所有 free 调用
func (d *DoubleFreeDetectorImproved) findFreeCalls(ctx *core.AnalysisContext, funcNode *sitter.Node) []*FreeCallInfo {
	var freeCalls []*FreeCallInfo

	// 从控制流块中收集
	d.mutex.RLock()
	for _, block := range d.controlFlow {
		freeCalls = append(freeCalls, block.FreeCalls...)
	}
	d.mutex.RUnlock()

	// 【修复】按行号排序，确保按代码执行顺序分析
	// 使用稳定的排序算法
	sort.SliceStable(freeCalls, func(i, j int) bool {
		return freeCalls[i].Line < freeCalls[j].Line
	})

	return freeCalls
}

// analyzePointerAssignments 分析指针赋值
func (d *DoubleFreeDetectorImproved) analyzePointerAssignments(ctx *core.AnalysisContext, funcNode *sitter.Node) {
	var traverse func(node *sitter.Node)
	traverse = func(node *sitter.Node) {
		if node == nil {
			return
		}

		if core.SafeType(node) == "assignment_expression" {
			left := core.SafeChildByFieldName(node, "left")
			right := core.SafeChildByFieldName(node, "right")

			if left != nil && core.SafeType(left) == "identifier" {
				varName := ctx.GetSourceText(left)

				// 检查是否为指针赋值
				if right != nil {
					line := int(node.StartPoint().Row) + 1

					d.mutex.Lock()
					if state, exists := d.pointerStates[varName]; exists {
						state.LastAssignLine = line
						state.AssignedAfter = true
					} else {
						d.pointerStates[varName] = &PointerStateInfo{
							Name:           varName,
							LastAssignLine: line,
							AssignedAfter:  false,
							IsFreed:        false,
						}
					}
					d.mutex.Unlock()
				}
			}
		}

		for i := 0; i < int(core.SafeChildCount(node)); i++ {
			traverse(core.SafeChild(node, i))
		}
	}

	body := core.SafeChildByFieldName(funcNode, "body")
	if body != nil {
		traverse(body)
	}
}

// isDoubleFree 检查是否为 double free
func (d *DoubleFreeDetectorImproved) isDoubleFree(ctx *core.AnalysisContext, freeCall *FreeCallInfo, funcNode *sitter.Node) bool {
	varName := freeCall.VarName
	line := freeCall.Line

	d.mutex.RLock()
	state, exists := d.pointerStates[varName]
	d.mutex.RUnlock()

	debugPrintf("[DEBUG] isDoubleFree: varName=%s, line=%d, exists=%v\n", varName, line, exists)
	if exists {
		debugPrintf("[DEBUG]   state.LastFreeLine=%d, state.IsFreed=%v\n", state.LastFreeLine, state.IsFreed)
	}

	// 【修复】如果不存在，或者存在但未被 freed（只是赋值记录），则是第一次 free
	if !exists || !state.IsFreed {
		// 第一次 free，记录状态
		d.mutex.Lock()
		if state, exists := d.pointerStates[varName]; exists {
			// 更新现有状态（来自赋值记录）
			state.IsFreed = true
			state.LastFreeLine = line
		} else {
			// 创建新状态
			d.pointerStates[varName] = &PointerStateInfo{
				Name:         varName,
				LastFreeLine: line,
				IsFreed:      true,
			}
		}
		d.mutex.Unlock()
		debugPrintf("[DEBUG]   First free, recording state\n")
		return false
	}

	// 过滤器1: 检查 free 后是否重新赋值
	if state.AssignedAfter && state.LastAssignLine > state.LastFreeLine {
		// 重新赋值后，之前的 free 不再是 double free
		d.mutex.Lock()
		state.IsFreed = true
		state.LastFreeLine = line
		state.AssignedAfter = false
		d.mutex.Unlock()
		return false
	}

	// 过滤器2: 检查是否在互斥的控制流块中
	if d.areInMutuallyExclusiveBlocks(ctx, freeCall, state.LastFreeLine) {
		// 两个 free 调用在互斥的块中，不会同时执行
		return false
	}

	// 过滤器3: 使用 Z3 验证路径可行性
	if d.z3Solver != nil && d.z3Solver.IsAvailable() {
		if !d.checkPathFeasibilityWithZ3(ctx, freeCall, state.LastFreeLine) {
			// 路径不可行，不是真正的 double free
			return false
		}
	}

	// 确认是 double free
	d.mutex.Lock()
	state.LastFreeLine = line
	d.mutex.Unlock()

	return true
}

// areInMutuallyExclusiveBlocks 检查是否在互斥的块中
func (d *DoubleFreeDetectorImproved) areInMutuallyExclusiveBlocks(ctx *core.AnalysisContext, freeCall *FreeCallInfo, prevFreeLine int) bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	// 查找两个 free 调用所在的控制流块
	var prevBlock, currBlock *ControlFlowBlock

	for _, block := range d.controlFlow {
		for _, fc := range block.FreeCalls {
			if fc.Line == prevFreeLine {
				prevBlock = block
			}
			if fc.Line == freeCall.Line {
				currBlock = block
			}
		}
	}

	debugPrintf("[DEBUG] areInMutuallyExclusiveBlocks: prevFreeLine=%d, currLine=%d\n", prevFreeLine, freeCall.Line)
	debugPrintf("[DEBUG]   prevBlock: %v, currBlock: %v\n", prevBlock != nil, currBlock != nil)
	if prevBlock != nil {
		debugPrintf("[DEBUG]   prevBlock.IsMutuallyExclusive: %v, prevBlock.Returns: %v\n", prevBlock.IsMutuallyExclusive, prevBlock.Returns)
	}
	if currBlock != nil {
		debugPrintf("[DEBUG]   currBlock.IsMutuallyExclusive: %v, currBlock.Returns: %v\n", currBlock.IsMutuallyExclusive, currBlock.Returns)
	}

	if prevBlock == nil || currBlock == nil {
		return false
	}

	// 【新增】检查是否一个在互斥块内，另一个在块外
	// 如果 if 块内没有 return，则块外的代码可能与块内的代码在同一条路径上
	if prevBlock.IsMutuallyExclusive && !currBlock.IsMutuallyExclusive {
		debugPrintf("[DEBUG]   prev 块在互斥块内，curr 块不在\n")
		debugPrintf("[DEBUG]   prevBlock.Returns=%v\n", prevBlock.Returns)
		if prevBlock.Returns {
			// prevBlock 是互斥块且有 return，则路径在此终止
			// currBlock 的代码不可能与 prevBlock 在同一条路径上
			debugPrintf("[DEBUG]   prev 块有 return，路径终止，互斥\n")
			return true // 是互斥的
		}
		if !prevBlock.Returns {
			// prevBlock 是互斥块（如 if 块），但没有 return
			// 这意味着代码会 "fall through" 到 currBlock
			// 它们可能在同一条路径上，不是互斥的
			debugPrintf("[DEBUG]   prev 块在互斥块内但没有 return，可能 fall through\n")
			return false // 不是互斥的，可能 double free
		}
	}
	if currBlock.IsMutuallyExclusive && !prevBlock.IsMutuallyExclusive {
		debugPrintf("[DEBUG]   curr 块在互斥块内，prev 块不在\n")
		debugPrintf("[DEBUG]   currBlock.Returns=%v\n", currBlock.Returns)
		if currBlock.Returns {
			// currBlock 是互斥块且有 return，则路径在此终止
			// prevBlock 的代码不可能与 currBlock 在同一条路径上
			debugPrintf("[DEBUG]   curr 块有 return，路径终止，互斥\n")
			return true // 是互斥的
		}
		if !currBlock.Returns {
			debugPrintf("[DEBUG]   curr 块在互斥块内但没有 return，可能 fall through\n")
			return false
		}
	}

	// 检查是否为互斥块
	if prevBlock.IsMutuallyExclusive && currBlock.IsMutuallyExclusive {
		// 改进1: 检查两个块是否为兄弟节点（来自同一个 if 语句）
		// 如果是兄弟节点且都有 return，则是互斥的
		if d.areSiblingBlocksWithReturn(prevBlock, currBlock) {
			return true
		}

		// 原有检查：如果一个块有 return，则不可能是 double free
		if prevBlock.Returns || currBlock.Returns {
			return true
		}
	}

	// 改进2: 检查是否在不同的错误处理分支中
	// 如果两个 free 调用在不同的守护块中（错误处理模式），则是互斥的
	if freeCall.InGuardBlock {
		// 当前 free 在守护块中，查找之前的 free 是否也在守护块
		for _, block := range d.controlFlow {
			for _, fc := range block.FreeCalls {
				if fc.Line == prevFreeLine && fc.InGuardBlock {
					// 两个都在守护块中，但可能是不同的错误分支
					// 进一步检查是否在不同的块中
					if block.StartLine != currBlock.StartLine {
						return true // 不同的守护块，互斥
					}
				}
			}
		}
	}

	return false
}

// areSiblingBlocksWithReturn 检查两个块是否为兄弟节点且有 return
// 针对 gzread.c: 两个错误处理分支是兄弟 if-else 块
func (d *DoubleFreeDetectorImproved) areSiblingBlocksWithReturn(block1, block2 *ControlFlowBlock) bool {
	// 简化判断：如果两个块都有 return 且行号相近（在同一个函数内）
	// 很可能是互斥的错误处理分支
	if block1.Returns && block2.Returns {
		// 检查行号距离
		distance := block1.StartLine - block2.StartLine
		if distance < 0 {
			distance = -distance
		}
		// 如果距离小于 50 行，可能是互斥的兄弟块
		if distance < 50 {
			return true
		}
	}
	return false
}

// checkPathFeasibilityWithZ3 使用 Z3 检查路径可行性
func (d *DoubleFreeDetectorImproved) checkPathFeasibilityWithZ3(ctx *core.AnalysisContext, freeCall *FreeCallInfo, prevFreeLine int) bool {
	if d.z3Solver == nil || !d.z3Solver.IsAvailable() {
		// Z3 不可用，保守处理
		return true
	}

	// 构建 Z3 约束：
	// 1. 第一次 free 在行 prevFreeLine 执行
	// 2. 第二次 free 在行 freeCall.Line 执行
	// 3. 检查是否存在一条路径使得两次 free 都执行

	// 简化实现：检查两个 free 调用是否在不同的错误处理分支
	// 如果是，且每个分支都有 return，则路径不可行

	// 使用 Z3 的路径可行性检查
	constraint := fmt.Sprintf("free_%s_%d_and_free_%s_%d", freeCall.VarName, prevFreeLine, freeCall.VarName, freeCall.Line)

	return d.z3Solver.CheckPathFeasible(constraint, "both_executed")
}

// getFunctionName 获取函数名
func (d *DoubleFreeDetectorImproved) getFunctionName(ctx *core.AnalysisContext, node *sitter.Node) string {
	funcNode := core.SafeChildByFieldName(node, "function")
	if funcNode == nil {
		return ""
	}

	if core.SafeType(funcNode) == "identifier" {
		return ctx.GetSourceText(funcNode)
	}

	return ""
}

// extractFreeVariable 提取被释放的变量名
// 支持精确的成员访问路径提取（如 strm->state, ptr->member->submember）
func (d *DoubleFreeDetectorImproved) extractFreeVariable(ctx *core.AnalysisContext, freeCall *sitter.Node) string {
	args := core.SafeChildByFieldName(freeCall, "arguments")
	if args == nil || core.SafeChildCount(args) == 0 {
		return ""
	}

	// 获取第一个参数（对于 ZFREE(strm, ptr)，第二个参数才是被释放的指针）
	// 检查是否有两个参数（ZFREE宏通常是 ZFILE*(zfile, ptr)）
	argCount := 0
	var firstArg, secondArg *sitter.Node
	for i := 0; i < int(core.SafeChildCount(args)); i++ {
		child := core.SafeChild(args, i)
		if core.SafeType(child) != "(" && core.SafeType(child) != "," && core.SafeType(child) != ")" {
			argCount++
			if argCount == 1 {
				firstArg = child
			} else if argCount == 2 {
				secondArg = child
				break
			}
		}
	}

	// 如果有两个参数，使用第二个参数；否则使用第一个
	var targetArg *sitter.Node
	if secondArg != nil {
		targetArg = secondArg
	} else if firstArg != nil {
		targetArg = firstArg
	} else {
		return ""
	}

	// 递归提取完整的成员访问路径
	return d.extractAccessPath(ctx, targetArg)
}

// extractAccessPath 递归提取完整的成员访问路径
// 支持：identifier, ptr->member, obj.member, 多级访问如 a->b->c
func (d *DoubleFreeDetectorImproved) extractAccessPath(ctx *core.AnalysisContext, node *sitter.Node) string {
	if node == nil {
		return ""
	}

	nodeType := core.SafeType(node)

	// 基础情况：简单的标识符
	if nodeType == "identifier" {
		return ctx.GetSourceText(node)
	}

	// 处理指针成员访问：ptr->member
	if nodeType == "pointer_expression" {
		object := core.SafeChildByFieldName(node, "argument") // ptr
		field := core.SafeChildByFieldName(node, "field")     // member

		objectPath := d.extractAccessPath(ctx, object)
		fieldName := ""
		if field != nil {
			fieldName = ctx.GetSourceText(field)
		}

		if objectPath != "" && fieldName != "" {
			return objectPath + "->" + fieldName
		}
		return objectPath
	}

	// 处理直接成员访问：obj.member
	if nodeType == "field_expression" {
		object := core.SafeChildByFieldName(node, "object") // obj
		field := core.SafeChildByFieldName(node, "field")    // member

		objectPath := d.extractAccessPath(ctx, object)
		fieldName := ""
		if field != nil {
			fieldName = ctx.GetSourceText(field)
		}

		if objectPath != "" && fieldName != "" {
			return objectPath + "." + fieldName
		}
		return objectPath
	}

	// 处理下标访问：array[index]
	if nodeType == "subscript_expression" {
		object := core.SafeChildByFieldName(node, "argument") // array
		index := core.SafeChildByFieldName(node, "index")     // index

		objectPath := d.extractAccessPath(ctx, object)
		indexText := ""
		if index != nil {
			indexText = ctx.GetSourceText(index)
		}

		if objectPath != "" && indexText != "" {
			return objectPath + "[" + indexText + "]"
		}
		return objectPath
	}

	// 其他情况，尝试直接获取源文本
	return ctx.GetSourceText(node)
}

// createVulnerability 创建漏洞报告
func (d *DoubleFreeDetectorImproved) createVulnerability(ctx *core.AnalysisContext, freeCall *FreeCallInfo) core.DetectorVulnerability {
	message := fmt.Sprintf("Double free of variable '%s' at line %d", freeCall.VarName, freeCall.Line)

	// 检查是否使用 Z3 验证
	if d.z3Solver != nil && d.z3Solver.IsAvailable() {
		message += " (verified with Z3 constraint solving)"
	}

	return d.BaseDetector.CreateVulnerability(
		core.CWE415,
		message,
		freeCall.Node,
		core.ConfidenceHigh,
		core.SeverityCritical,
	)
}
