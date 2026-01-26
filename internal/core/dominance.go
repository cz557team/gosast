package core

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// DominanceTree 支配树
// 用于SSA构建中的φ函数放置
type DominanceTree struct {
	ImmediateDominator map[int]int      // 节点ID -> 直接支配者ID
	DominatorTree      map[int][]int    // 节点ID -> 被支配节点列表
	DominanceFrontiers map[int][]int    // 节点ID -> 支配边界列表
	cfg                *CFG
}

// NewDominanceTree 创建支配树
func NewDominanceTree(cfg *CFG) *DominanceTree {
	return &DominanceTree{
		ImmediateDominator: make(map[int]int),
		DominatorTree:      make(map[int][]int),
		DominanceFrontiers: make(map[int][]int),
		cfg:                cfg,
	}
}

// Compute 计算支配关系和支配边界
func (dt *DominanceTree) Compute() error {
	if dt.cfg == nil || len(dt.cfg.Nodes) == 0 {
		return nil
	}

	// 1. 计算直接支配者（使用迭代算法）
	dt.computeImmediateDominators()

	// 2. 构建支配树
	dt.buildDominatorTree()

	// 3. 计算支配边界（用于φ函数放置）
	dt.computeDominanceFrontiers()

	return nil
}

// computeImmediateDominators 计算直接支配者
// 使用Cooper-Harvey-Kennedy算法的简化版本
func (dt *DominanceTree) computeImmediateDominators() {
	nodes := dt.cfg.Nodes
	if len(nodes) == 0 {
		return
	}

	entry := dt.cfg.Entry
	if entry == nil {
		return
	}

	// 初始化：入口节点的直接支配者是它自己（特殊标记）
	dt.ImmediateDominator[entry.ID] = entry.ID

	// 其他节点的直接支配者初始化为undefined
	changed := true
	for changed {
		changed = false

		for _, node := range nodes {
			if node.ID == entry.ID {
				continue
			}

			// 找到前驱节点的直接支配者的交集
			var newIDom int
			firstPred := true

			for _, pred := range node.Predecessors {
				if dt.ImmediateDominator[pred.ID] == 0 {
					// 前驱的支配者还未计算
					continue
				}

				if firstPred {
					newIDom = pred.ID
					firstPred = false
				} else {
					newIDom = dt.intersectDominators(pred.ID, newIDom)
				}
			}

			if newIDom != 0 && dt.ImmediateDominator[node.ID] != newIDom {
				dt.ImmediateDominator[node.ID] = newIDom
				changed = true
			}
		}
	}
}

// intersectDominators 计算两个节点的支配者交集
func (dt *DominanceTree) intersectDominators(id1, id2 int) int {
	finger1 := id1
	finger2 := id2

	for finger1 != finger2 {
		for finger1 > finger2 {
			idom := dt.ImmediateDominator[finger1]
			if idom == 0 {
				break
			}
			finger1 = idom
		}
		for finger2 > finger1 {
			idom := dt.ImmediateDominator[finger2]
			if idom == 0 {
				break
			}
			finger2 = idom
		}
	}

	return finger1
}

// buildDominatorTree 构建支配树
func (dt *DominanceTree) buildDominatorTree() {
	for nodeID, idomID := range dt.ImmediateDominator {
		if nodeID == idomID {
			// 入口节点，跳过
			continue
		}

		// 添加到支配者的子节点列表
		dt.DominatorTree[idomID] = append(dt.DominatorTree[idomID], nodeID)
	}
}

// computeDominanceFrontiers 计算支配边界
// 支配边界：节点d严格支配节点a，且d不严格支配a的前驱，则d在a的支配边界中
func (dt *DominanceTree) computeDominanceFrontiers() {
	nodes := dt.cfg.Nodes

	// 对每个节点，计算其支配边界
	for _, node := range nodes {
		if len(node.Predecessors) < 2 {
			// 只有一个或没有前驱的节点，支配边界为空
			continue
		}

		// 对于多个前驱的情况
		for _, pred := range node.Predecessors {
			runner := pred.ID

			// 从前驱向上遍历支配树，直到当前节点的直接支配者
			for runner != dt.ImmediateDominator[node.ID] {
				// 将当前节点加入runner的支配边界
				dt.DominanceFrontiers[runner] = append(dt.DominanceFrontiers[runner], node.ID)

				// 移动到runner的直接支配者
				idom := dt.ImmediateDominator[runner]
				if idom == 0 || idom == runner {
					break
				}
				runner = idom
			}
		}
	}
}

// GetDominanceFrontier 获取节点的支配边界
func (dt *DominanceTree) GetDominanceFrontier(nodeID int) []int {
	if df, ok := dt.DominanceFrontiers[nodeID]; ok {
		return df
	}
	return []int{}
}

// GetDominatorTreeChildren 获取支配树子节点
func (dt *DominanceTree) GetDominatorTreeChildren(nodeID int) []int {
	if children, ok := dt.DominatorTree[nodeID]; ok {
		return children
	}
	return []int{}
}

// ImmediateDominatorOf 获取节点的直接支配者
func (dt *DominanceTree) ImmediateDominatorOf(nodeID int) (int, bool) {
	idom, ok := dt.ImmediateDominator[nodeID]
	if ok && idom != nodeID {
		return idom, true
	}
	return 0, false
}

// Dominates 检查node1是否支配node2
func (dt *DominanceTree) Dominates(nodeID1, nodeID2 int) bool {
	if nodeID1 == nodeID2 {
		return true
	}

	current := nodeID2
	for current != 0 {
		idom, ok := dt.ImmediateDominator[current]
		if !ok {
			break
		}

		if idom == nodeID1 {
			return true
		}

		if idom == current {
			// 到达入口节点
			break
		}

		current = idom
	}

	return false
}

// =============================================================================
// SSA构建辅助函数
// =============================================================================

// InsertPhiNodes 计算并返回每个基本块需要插入的φ函数
// 为每个变量的定义点的支配边界插入φ函数
func (dt *DominanceTree) InsertPhiNodes(
	definitions map[string][]int, // 变量名 -> 定义点列表
) map[int][]string {
	// 基本块ID -> 需要插入φ函数的变量列表
	phiNodes := make(map[int][]string)

	// 工作列表算法
	hasAlready := make(map[string]map[int]bool)
	workList := make(map[string][]int)

	// 初始化工作列表
	for varName, defBlocks := range definitions {
		if hasAlready[varName] == nil {
			hasAlready[varName] = make(map[int]bool)
		}
		workList[varName] = make([]int, 0, len(defBlocks))
		workList[varName] = append(workList[varName], defBlocks...)
	}

	// 处理工作列表
	for len(workList) > 0 {
		// 取出一个变量
		var varName string
		for v := range workList {
			varName = v
			break
		}

		// 取出该变量的一个工作块
		var workBlock int
		workBlocks := workList[varName]
		workBlock = workBlocks[len(workBlocks)-1]
		workList[varName] = workBlocks[:len(workBlocks)-1]

		if len(workList[varName]) == 0 {
			delete(workList, varName)
		}

		// 对于该块的支配边界
		for _, frontierBlock := range dt.GetDominanceFrontier(workBlock) {
			// 如果该边界块还没有这个变量的φ函数
			if !hasAlready[varName][frontierBlock] {
				// 添加φ函数
				phiNodes[frontierBlock] = append(phiNodes[frontierBlock], varName)
				hasAlready[varName][frontierBlock] = true

				// 如果该块不是定义块，加入工作列表
				isDefBlock := false
				for _, defBlock := range definitions[varName] {
					if defBlock == frontierBlock {
						isDefBlock = true
						break
					}
				}

				if !isDefBlock {
					workList[varName] = append(workList[varName], frontierBlock)
				}
			}
		}
	}

	return phiNodes
}

// =============================================================================
// CFG扩展 - 添加基本块到语句的映射
// =============================================================================

// AddStatementToBlock 向CFG节点添加语句（用于AST到CFG的映射）
func (cfg *CFG) AddStatementToBlock(nodeID int, stmt *sitter.Node) {
	if cfg == nil {
		return
	}

	for _, node := range cfg.Nodes {
		if node.ID == nodeID {
			node.Statements = append(node.Statements, stmt)
			return
		}
	}
}

// FindBlockContainingStatement 查找包含语句的CFG基本块
func (cfg *CFG) FindBlockContainingStatement(stmt *sitter.Node) *CFGNode {
	if cfg == nil || stmt == nil {
		return nil
	}

	stmtStart := stmt.StartByte()
	stmtEnd := stmt.EndByte()

	for _, node := range cfg.Nodes {
		for _, nodeStmt := range node.Statements {
			stmtStart2 := nodeStmt.StartByte()
			stmtEnd2 := nodeStmt.EndByte()

			// 检查字节范围是否重叠
			if stmtStart >= stmtStart2 && stmtEnd <= stmtEnd2 {
				return node
			}
		}
	}

	return nil
}
