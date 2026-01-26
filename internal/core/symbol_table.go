package core

import (
	"sync"
	"sync/atomic"
)

// SymbolType 符号类型
type SymbolType int

const (
	SymbolFunction SymbolType = iota
	SymbolVariable
	SymbolTypeDef
	SymbolMacro
)

// Symbol 符号信息
type Symbol struct {
	Name       string      `json:"name"`       // 符号名称
	Type       SymbolType  `json:"type"`       // 符号类型
	FilePath   string      `json:"file_path"`  // 定义文件路径
	Line       int         `json:"line"`       // 定义行号
	Column     int         `json:"column"`     // 定义列号
	Signature  string      `json:"signature"`  // 函数签名或变量类型
	IsExported bool        `json:"is_exported"` // 是否为导出符号
	ASTNode    interface{} `json:"-"`          // AST节点（可选）
}

// CallSite 调用点信息
type CallSite struct {
	CalleeName string      `json:"callee_name"` // 被调用函数名
	CallerFile string      `json:"caller_file"` // 调用者文件
	CallerLine int         `json:"caller_line"` // 调用行号
	CallerNode interface{} `json:"-"`           // 调用节点
	Arguments  []interface{} `json:"-"`         // 调用参数
}

// SymbolTable 符号表（性能优化版）
// 使用两阶段模式：构建阶段使用 mutex，分析阶段使用原子快照（无锁读取）
type SymbolTable struct {
	// 原子快照：发布后只读，无锁访问
	snapshots atomic.Value  // *symbolSnapshots
	// 构建阶段使用
	mu sync.Mutex
}

// symbolSnapshots 符号表快照（不可变）
type symbolSnapshots struct {
	symbols     map[string][]*Symbol
	fileSymbols map[string][]*Symbol
}

// NewSymbolTable 创建新的符号表
func NewSymbolTable() *SymbolTable {
	st := &SymbolTable{}
	// 初始化空的快照
	st.snapshots.Store(&symbolSnapshots{
		symbols:     make(map[string][]*Symbol),
		fileSymbols: make(map[string][]*Symbol),
	})
	return st
}

// AddSymbol 添加符号（构建阶段）
func (st *SymbolTable) AddSymbol(symbol *Symbol) {
	st.mu.Lock()
	defer st.mu.Unlock()

	current := st.snapshots.Load().(*symbolSnapshots)

	// 创建新的快照（写时复制）
	newSnap := &symbolSnapshots{
		symbols:     make(map[string][]*Symbol, len(current.symbols)),
		fileSymbols: make(map[string][]*Symbol, len(current.fileSymbols)),
	}

	// 复制现有数据
	for k, v := range current.symbols {
		newSnap.symbols[k] = v
	}
	for k, v := range current.fileSymbols {
		newSnap.fileSymbols[k] = v
	}

	// 添加新符号
	newSnap.symbols[symbol.Name] = append(newSnap.symbols[symbol.Name], symbol)
	newSnap.fileSymbols[symbol.FilePath] = append(newSnap.fileSymbols[symbol.FilePath], symbol)

	// 发布新快照
	st.snapshots.Store(newSnap)
}

// Publish 完成构建，发布最终快照（可选优化）
func (st *SymbolTable) Publish() {
	// 快照已经在 AddSymbol 中自动更新，这里可以做一些最终优化
	// 例如：整理数据结构，压缩内存等
}

// GetSymbols 获取指定名称的所有符号（无锁读取）
func (st *SymbolTable) GetSymbols(name string) []*Symbol {
	snap := st.snapshots.Load().(*symbolSnapshots)
	return snap.symbols[name]
}

// GetSymbol 获取指定名称和文件路径的符号（无锁读取）
func (st *SymbolTable) GetSymbol(name, filePath string) *Symbol {
	snap := st.snapshots.Load().(*symbolSnapshots)

	symbols := snap.symbols[name]
	for _, sym := range symbols {
		if sym.FilePath == filePath {
			return sym
		}
	}

	// 如果在当前文件找不到，尝试找第一个匹配的
	if len(symbols) > 0 {
		return symbols[0]
	}

	return nil
}

// GetFileSymbols 获取指定文件的所有符号（无锁读取）
func (st *SymbolTable) GetFileSymbols(filePath string) []*Symbol {
	snap := st.snapshots.Load().(*symbolSnapshots)
	return snap.fileSymbols[filePath]
}

// GetAllSymbols 获取所有符号（无锁读取）
func (st *SymbolTable) GetAllSymbols() []*Symbol {
	snap := st.snapshots.Load().(*symbolSnapshots)

	var all []*Symbol
	for _, symbols := range snap.symbols {
		all = append(all, symbols...)
	}
	return all
}

// SymbolStats 符号表统计信息
type SymbolStats struct {
	TotalSymbols  int            `json:"total_symbols"`
	ByType        map[SymbolType]int `json:"by_type"`
	ByFile        map[string]int `json:"by_file"`
	ExportedCount int            `json:"exported_count"`
}

// GetStats 获取统计信息（无锁读取）
func (st *SymbolTable) GetStats() *SymbolStats {
	snap := st.snapshots.Load().(*symbolSnapshots)

	stats := &SymbolStats{
		ByType: make(map[SymbolType]int),
		ByFile: make(map[string]int),
	}

	for _, symbols := range snap.symbols {
		stats.TotalSymbols += len(symbols)
		for _, sym := range symbols {
			stats.ByType[sym.Type]++
			if sym.IsExported {
				stats.ExportedCount++
			}
			stats.ByFile[sym.FilePath]++
		}
	}

	return stats
}

// ResolveCall 解析函数调用
func (st *SymbolTable) ResolveCall(callSite *CallSite) *Symbol {
	return st.GetSymbol(callSite.CalleeName, callSite.CallerFile)
}

// HasSymbol 检查符号是否存在（无锁读取）
func (st *SymbolTable) HasSymbol(name string) bool {
	snap := st.snapshots.Load().(*symbolSnapshots)
	_, exists := snap.symbols[name]
	return exists
}

// Clear 清空符号表
func (st *SymbolTable) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()

	// 创建新的空快照
	st.snapshots.Store(&symbolSnapshots{
		symbols:     make(map[string][]*Symbol),
		fileSymbols: make(map[string][]*Symbol),
	})
}
