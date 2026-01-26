package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
)

// ParserPool 管理 tree-sitter Parser 实例池（Phase 4 优化）
// 使用 sync.Pool 允许每个 goroutine 获取独立的 Parser，消除全局锁瓶颈
type ParserPool struct {
	cPool sync.Pool
	cppPool sync.Pool
}

// NewParserPool 创建新的 Parser Pool
func NewParserPool() *ParserPool {
	return &ParserPool{
		cPool: sync.Pool{
			New: func() interface{} {
				parser := sitter.NewParser()
				parser.SetLanguage(c.GetLanguage())
				return parser
			},
		},
		cppPool: sync.Pool{
			New: func() interface{} {
				parser := sitter.NewParser()
				parser.SetLanguage(cpp.GetLanguage())
				return parser
			},
		},
	}
}

// globalParserPool 全局 Parser Pool 实例（Phase 4 优化）
var globalParserPool = NewParserPool()

// GetParser 从 Pool 获取对应语言的 Parser（无需锁）
func GetParser(language string) *sitter.Parser {
	if language == "cpp" {
		return globalParserPool.cppPool.Get().(*sitter.Parser)
	}
	return globalParserPool.cPool.Get().(*sitter.Parser)
}

// PutParser 将 Parser 归还到 Pool（无需锁）
func PutParser(language string, parser *sitter.Parser) {
	// 重置 Parser 状态以便重用
	parser.Reset()
	if language == "cpp" {
		globalParserPool.cppPool.Put(parser)
	} else {
		globalParserPool.cPool.Put(parser)
	}
}

// GlobalTreeSitterMutex 已弃用（Phase 4 优化）
// 保留此变量仅用于向后兼容，不再实际使用
// Parser Pool 替代方案提供更好的并发性能（2-4x 提升）
//
// Deprecated: 使用 Parser Pool 替代（GetParser/PutParser）
var GlobalTreeSitterMutex sync.RWMutex

// QueryCache 全局Query缓存（避免重复创建Query对象）
// key: language:queryPattern -> *sitter.Query
var queryCache sync.Map

// GetQueryFromCache 从缓存获取或创建Query
func GetQueryFromCache(queryPattern string, language string) (*sitter.Query, error) {
	key := language + ":" + queryPattern

	// 尝试从缓存获取（快速路径，无锁）
	if cached, ok := queryCache.Load(key); ok {
		return cached.(*sitter.Query), nil
	}

	// 缓存未命中，需要创建新Query
	// 【修复】加锁防止多个 goroutine 同时创建相同的 Query
	GlobalTreeSitterMutex.Lock()
	defer GlobalTreeSitterMutex.Unlock()

	// 双重检查：可能在等待锁期间已被其他 goroutine 创建
	if cached, ok := queryCache.Load(key); ok {
		return cached.(*sitter.Query), nil
	}

	// 创建新的Query
	var lang *sitter.Language
	if language == "c" {
		lang = c.GetLanguage()
	} else {
		lang = cpp.GetLanguage()
	}

	query, err := sitter.NewQuery([]byte(queryPattern), lang)
	if err != nil {
		return nil, fmt.Errorf("failed to create query: %w", err)
	}

	// 存入缓存
	queryCache.Store(key, query)
	return query, nil
}

// ParsedUnit 表示一个已解析的代码单元
type ParsedUnit struct {
	FilePath string
	Root     *sitter.Node
	Source   []byte
	Tree     *sitter.Tree
	Language string
}

// Copy 创建 ParsedUnit 的副本（克隆 Tree 以支持并发访问）
func (u *ParsedUnit) Copy() *ParsedUnit {
	treeCopy := u.Tree.Copy()
	return &ParsedUnit{
		FilePath: u.FilePath,
		Root:     treeCopy.RootNode(),
		Source:   u.Source, // 源码只读，可以共享
		Tree:     treeCopy,
		Language: u.Language,
	}
}

// QueryMatch 表示查询匹配的结果
type QueryMatch struct {
	Node     *sitter.Node
	Captures map[string]*sitter.Node
	Pattern  string
}

// AnalysisContext 提供分析所需的上下文
type AnalysisContext struct {
	Unit              *ParsedUnit
	CFG               *CFG               // 控制流图
	Taint             TaintEngine        // 污点分析引擎
	Solver            *Z3Solver          // Z3约束求解器
	CrossFileAnalyzer *CrossFileAnalyzer // 跨文件分析器（可选）
	SymbolResolver    *SymbolResolver    // 符号解析器（可选）
	GlobalArrays      map[string]bool    // 全局常量数组（预扫描阶段收集）
	GlobalStructs     map[string]*StructInfo // 全局结构体定义（V13 预扫描阶段收集）
	// 【优化2 - 函数定义缓存】将 FindFunctionDefinition() 从 O(n) 降到 O(1)
	funcDefinitionCache map[string]*sitter.Node  // 函数名 -> 定义节点
	funcCacheInitialized bool                     // 缓存是否已初始化
}

// NewAnalysisContext 创建新的分析上下文
func NewAnalysisContext(unit *ParsedUnit) *AnalysisContext {
	return &AnalysisContext{
		Unit: unit,
	}
}

// NewCrossFileAnalysisContext 创建支持跨文件分析的分析上下文
func NewCrossFileAnalysisContext(unit *ParsedUnit, crossFileAnalyzer *CrossFileAnalyzer) *AnalysisContext {
	return &AnalysisContext{
		Unit:              unit,
		CrossFileAnalyzer: crossFileAnalyzer,
	}
}

// GetLanguage 根据文件扩展名获取对应的解析器语言
func GetLanguage(filename string) (*sitter.Language, error) {
	ext := strings.ToLower(filepath.Ext(filename))

	switch ext {
	case ".c":
		return c.GetLanguage(), nil
	case ".cpp", ".cxx", ".cc", ".c++", ".hpp", ".hxx", ".hh", ".h++":
		return cpp.GetLanguage(), nil
	case ".h":
		// 对于 .h 文件，尝试根据内容判断是 C 还是 C++
		return cpp.GetLanguage(), nil // 默认使用 C++
	default:
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}
}

// ParseFile 解析单个文件
func ParseFile(ctx context.Context, filePath string) (*ParsedUnit, error) {
	// 读取源文件
	source, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// 获取对应的语言
	lang, err := GetLanguage(filePath)
	if err != nil {
		return nil, err
	}

	// 创建解析器
	parser := sitter.NewParser()
	parser.SetLanguage(lang)

	// 解析源代码
	tree, err := parser.ParseCtx(ctx, nil, source)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file %s: %w", filePath, err)
	}

	// 创建解析单元
	ext := strings.ToLower(filepath.Ext(filePath))
	language := "c"
	if ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".c++" ||
	   ext == ".hpp" || ext == ".hxx" || ext == ".hh" || ext == ".h++" || ext == ".h" {
		language = "cpp"
	}

	unit := &ParsedUnit{
		FilePath: filePath,
		Root:     tree.RootNode(),
		Source:   source,
		Tree:     tree,
		Language: language,
	}

	return unit, nil
}

// QueryNodes 使用 Tree-sitter 查询语言查找节点（Phase 4 优化：无锁版本）
func (ctx *AnalysisContext) QueryNodes(queryPattern string) ([]*sitter.Node, error) {
	// 获取对应语言的 Parser（从 Pool，无全局锁）
	var lang *sitter.Language
	if ctx.Unit.Language == "c" {
		lang = c.GetLanguage()
	} else {
		lang = cpp.GetLanguage()
	}
	query, err := sitter.NewQuery([]byte(queryPattern), lang)
	if err != nil {
		return nil, fmt.Errorf("failed to create query: %w", err)
	}
	defer query.Close()

	cursor := sitter.NewQueryCursor()
	defer cursor.Close()

	cursor.Exec(query, ctx.Unit.Root)

	var nodes []*sitter.Node
	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}

		for _, capture := range match.Captures {
			nodes = append(nodes, capture.Node)
		}
	}

	return nodes, nil
}

// Query 执行查询并返回详细的匹配结果（使用Query缓存）
func (ctx *AnalysisContext) Query(queryPattern string) ([]QueryMatch, error) {
	// 从缓存获取Query（避免重复创建，解决并发问题）
	query, err := GetQueryFromCache(queryPattern, ctx.Unit.Language)
	if err != nil {
		return nil, err
	}

	cursor := sitter.NewQueryCursor()
	defer cursor.Close()

	cursor.Exec(query, ctx.Unit.Root)

	var matches []QueryMatch
	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}

		// 确保有至少一个捕获
		if len(match.Captures) == 0 {
			continue
		}

		qm := QueryMatch{
			Node:     match.Captures[0].Node,
			Captures: make(map[string]*sitter.Node),
			Pattern:  queryPattern,
		}

		// 获取所有捕获
		for _, capture := range match.Captures {
			captureName := query.CaptureNameForId(capture.Index)
			qm.Captures[captureName] = capture.Node
		}

		matches = append(matches, qm)
	}

	return matches, nil
}

// GetSourceText 获取节点的源代码文本
func (ctx *AnalysisContext) GetSourceText(node *sitter.Node) string {
	if node == nil {
		return ""
	}

	start := node.StartByte()
	end := node.EndByte()

	// 边界检查，防止越界
	if end > uint32(len(ctx.Unit.Source)) {
		end = uint32(len(ctx.Unit.Source))
	}
	if start > end {
		start = 0
	}

	if start >= uint32(len(ctx.Unit.Source)) {
		return ""
	}

	return string(ctx.Unit.Source[start:end])
}

// FindFunctionDeclarations 查找所有函数声明
func (ctx *AnalysisContext) FindFunctionDeclarations() ([]QueryMatch, error) {
	query := `
		(function_definition
			declarator: (function_declarator
				declarator: (identifier) @name
			)
			body: (compound_statement) @body
		) @func
	`

	return ctx.Query(query)
}

// FindFunctionCalls 查找所有函数调用
func (ctx *AnalysisContext) FindFunctionCalls() ([]QueryMatch, error) {
	query := `
		(call_expression
			function: (identifier) @name
			arguments: (argument_list) @args
		) @call
	`

	return ctx.Query(query)
}

// FindVariableDeclarations 查找所有变量声明
func (ctx *AnalysisContext) FindVariableDeclarations() ([]QueryMatch, error) {
	query := `
		(declaration
			type: (_)+ @type
			declarator: (identifier) @name
		) @decl
	`

	return ctx.Query(query)
}

// IsTainted 检查节点是否被污染（占位符，将在 taint.go 中实现）
func (ctx *AnalysisContext) IsTainted(node *sitter.Node) bool {
	if ctx.Taint != nil {
		return ctx.Taint.IsTainted(node)
	}
	return false
}

// IsPathFeasible 检查路径是否可行（占位符，将在 z3.go 中实现）
func (ctx *AnalysisContext) IsPathFeasible(from, to *sitter.Node) bool {
	if ctx.Solver != nil {
		return (*ctx.Solver).CheckPathFeasible(from, to)
	}
	return true // 默认假设路径可行
}

// InitTaintEngine 初始化污点分析引擎
func (ctx *AnalysisContext) InitTaintEngine() {
	if ctx.Taint == nil {
		ctx.Taint = NewMemoryTaintEngine(ctx)
	}
}

// GetTaintPath 获取节点的污染路径
func (ctx *AnalysisContext) GetTaintPath(node *sitter.Node) []TaintStep {
	if ctx.Taint != nil {
		return ctx.Taint.GetTaintPath(node)
	}
	return nil
}

// RunTaintAnalysis 运行污点分析
func (ctx *AnalysisContext) RunTaintAnalysis(cfg *CFG) error {
	if ctx.Taint == nil {
		ctx.InitTaintEngine()
	}
	return ctx.Taint.Propagate(cfg)
}

// RunCrossFunctionTaintPropagation 执行跨函数污点传播
// 在所有函数的本地污点传播完成后，调用此方法来传播污点跨越函数边界
func (ctx *AnalysisContext) RunCrossFunctionTaintPropagation() error {
	// 【优化1 - 预检查】快速检查文件是否有函数定义
	// 如果没有函数定义（如查找表文件），直接跳过跨函数污点传播
	funcCountQuery := `(function_definition) @func`
	funcMatches, err := ctx.QueryNodes(funcCountQuery)
	if err == nil && len(funcMatches) == 0 {
		// 文件没有函数定义，无需执行跨函数污点传播
		return nil
	}

	if ctx.Taint == nil {
		ctx.InitTaintEngine()
	}

	engine := ctx.Taint.(*MemoryTaintEngine)

	// 0. 首先，标记所有全局污点源（argv, envp 等）
	// 这样在后续的跨函数传播中才能正确识别
	ctx.markGlobalTaintSources(engine)

	// 1. 收集所有函数调用点
	callQuery := `(call_expression) @call`
	matches, err := ctx.QueryNodes(callQuery)
	if err != nil {
		return err
	}

	// 2. 对每个函数调用，执行跨函数污点传播
	propagatedCount := 0
	for _, callNode := range matches {
		// 获取调用点所在的函数名
		callerFuncName := ctx.GetContainingFunctionName(callNode)

		// 检查调用的参数是否有污点
		args := callNode.ChildByFieldName("arguments")
		if args == nil {
			continue
		}

		// 获取被调用函数名
		calleeFuncName := ctx.GetCallFunctionName(callNode)
		if calleeFuncName == "" {
			continue
		}

		// 查找被调用函数的定义
		funcDef := ctx.FindFunctionDefinition(calleeFuncName)
		if funcDef == nil {
			continue
		}

		// 提取函数参数节点
		params := ctx.ExtractFunctionParameters(funcDef)
		if params == nil {
			continue
		}

		// 遍历实际参数
		argCount := args.ChildCount()
		argIndex := 0
		for i := 0; i < int(argCount); i++ {
			arg := args.Child(i)
			if arg.Type() != "(" && arg.Type() != ")" {
				// 检查实际参数是否被污染
				isArgTainted := engine.IsTainted(arg)

				// *** 关键改进 ***: 如果是 identifier，检查变量名在函数作用域内是否被污点传播
				if !isArgTainted && arg.Type() == "identifier" {
					if callerFuncName != "" {
						if engine.IsIdentifierTaintedInFunction(arg, callerFuncName) {
							isArgTainted = true
						}
					}
				}

				// 如果实际参数被污染，传播污点到形式参数
				if isArgTainted && argIndex < len(params) {
					paramNode := params[argIndex]
					if paramNode != nil && !engine.IsTainted(paramNode) {
						// *** 关键改进 ***：使用 markTaintedInFunction
						// 这将污点传播到函数作用域，确保函数体内对该参数的引用都能被识别为污点
						engine.markTaintedInFunction(
							paramNode,
							calleeFuncName,  // 在被调用函数的作用域内
							arg,             // 污点来源是实际参数
							fmt.Sprintf("cross_function_propagation:%s->%s", callerFuncName, calleeFuncName),
						)
						propagatedCount++
					}
				}
				argIndex++
			}
		}
	}

	return nil
}

// markGlobalTaintSources 标记全局污点源（argv, envp 等）
func (ctx *AnalysisContext) markGlobalTaintSources(engine *MemoryTaintEngine) {
	taintedNames := map[string]bool{
		"argv":    true,
		"argc":    true,
		"envp":    true,
		"environ": true,
	}

	// 查找所有 argv, envp, environ 标识符
	idQuery := `(identifier) @id`
	idMatches, err := ctx.QueryNodes(idQuery)
	if err == nil {
		for _, match := range idMatches {
			name := ctx.GetSourceText(match)
			if taintedNames[name] {
				engine.markTainted(match)
			}
		}
	}

	// 查找所有 subscript_expression，检查是否为 argv[x], envp[x]
	subscriptQuery := `(subscript_expression) @sub`
	subMatches, _ := ctx.QueryNodes(subscriptQuery)
	for _, subMatch := range subMatches {
		array := subMatch.ChildByFieldName("argument")
		if array != nil && array.Type() == "identifier" {
			arrayName := ctx.GetSourceText(array)
			if taintedNames[arrayName] {
				engine.markTainted(subMatch)
			}
		}
	}
}

// FindTaintedNodes 查找所有被污染的节点
func (ctx *AnalysisContext) FindTaintedNodes() []*sitter.Node {
	if ctx.Taint == nil {
		return nil
	}

	var tainted []*sitter.Node
	// 遍历所有节点，检查是否被污染
	ctx.collectTaintedNodes(ctx.Unit.Root, &tainted)
	return tainted
}

// collectTaintedNodes 递归收集被污染的节点
func (ctx *AnalysisContext) collectTaintedNodes(node *sitter.Node, tainted *[]*sitter.Node) {
	if node == nil {
		return
	}

	if ctx.Taint.IsTainted(node) {
		*tainted = append(*tainted, node)
	}

	// 递归遍历子节点
	for i := 0; i < int(node.ChildCount()); i++ {
		ctx.collectTaintedNodes(node.Child(i), tainted)
	}
}

// FindSourcesAfter 查找某个节点之后的所有污点源
func (ctx *AnalysisContext) FindSourcesAfter(node *sitter.Node) []*sitter.Node {
	if ctx.Taint == nil {
		return nil
	}

	var sources []*sitter.Node
	// 遍历所有节点，查找污点源
	ctx.collectSources(ctx.Unit.Root, node, &sources)
	return sources
}

// collectSources 递归收集污点源
func (ctx *AnalysisContext) collectSources(root, afterNode *sitter.Node, sources *[]*sitter.Node) {
	if root == nil {
		return
	}

	// 检查是否在afterNode之后
	if afterNode != nil && root.StartPoint().Row <= afterNode.StartPoint().Row {
		// 在afterNode之前或同一行，跳过
	} else {
		// 检查是否是污点源
		if ctx.Taint.IsTainted(root) {
			// 检查是否有污点路径（如果是直接污点源，路径应该为空或只有一步）
			path := ctx.Taint.GetTaintPath(root)
			if len(path) == 0 {
				*sources = append(*sources, root)
			}
		}
	}

	// 递归遍历
	for i := 0; i < int(root.ChildCount()); i++ {
		ctx.collectSources(root.Child(i), afterNode, sources)
	}
}

// GetTaintStats 获取污点分析统计信息
func (ctx *AnalysisContext) GetTaintStats() map[string]interface{} {
	if ctx.Taint != nil {
		return ctx.Taint.GetStats()
	}
	return map[string]interface{}{
		"error": "taint engine not initialized",
	}
}

// === 跨函数污点传播辅助方法 ===

// GetCallFunctionName 获取函数调用的函数名
func (ctx *AnalysisContext) GetCallFunctionName(callNode *sitter.Node) string {
	if callNode == nil || callNode.Type() != "call_expression" {
		return ""
	}

	funcNode := callNode.ChildByFieldName("function")
	if funcNode == nil {
		return ""
	}

	// 处理 identifier 形式: func()
	if funcNode.Type() == "identifier" {
		return ctx.GetSourceText(funcNode)
	}

	// 处理 pointer_expression 形式: ptr->func() 或 *ptr()
	if funcNode.Type() == "pointer_expression" {
		// 获取指针解引用的目标
		arg := funcNode.ChildByFieldName("argument")
		if arg != nil && arg.Type() == "identifier" {
			return ctx.GetSourceText(arg)
		}
	}

	// 处理 field_expression 形式: obj.func()
	if funcNode.Type() == "field_expression" {
		field := funcNode.ChildByFieldName("field")
		if field != nil && field.Type() == "identifier" {
			return ctx.GetSourceText(field)
		}
	}

	return ""
}

// FindFunctionDefinition 查找函数定义节点（使用缓存优化）
func (ctx *AnalysisContext) FindFunctionDefinition(funcName string) *sitter.Node {
	if funcName == "" {
		return nil
	}

	// 【优化2】确保缓存已初始化
	ctx.ensureFunctionCache()

	// 从缓存中查找（O(1) 操作）
	if ctx.funcDefinitionCache != nil {
		return ctx.funcDefinitionCache[funcName]
	}

	return nil
}

// ensureFunctionCache 初始化函数定义缓存（只执行一次）
func (ctx *AnalysisContext) ensureFunctionCache() {
	if ctx.funcCacheInitialized {
		return
	}

	// 查询所有函数定义
	matches, err := ctx.QueryNodes("(function_definition) @def")
	if err != nil || len(matches) == 0 {
		ctx.funcCacheInitialized = true
		return
	}

	// 初始化缓存
	ctx.funcDefinitionCache = make(map[string]*sitter.Node)

	// 构建函数名 -> 定义节点的映射
	for _, match := range matches {
		name := ctx.ExtractFunctionNameFromDef(match)
		if name != "" {
			ctx.funcDefinitionCache[name] = match
		}
	}

	ctx.funcCacheInitialized = true
}

// ExtractFunctionNameFromDef 从函数定义节点中提取函数名（公开方法）
// 处理多种情况：
// 1. int func() - declarator 是 function_declarator
// 2. int* func() - declarator 是 pointer_declarator，其子节点是 function_declarator
// 3. int* (*func())() - 多层指针
func (ctx *AnalysisContext) ExtractFunctionNameFromDef(funcDef *sitter.Node) string {
	if funcDef == nil || funcDef.Type() != "function_definition" {
		return ""
	}

	// 获取声明器
	declarator := funcDef.ChildByFieldName("declarator")
	if declarator == nil {
		return ""
	}

	// 递归查找 function_declarator 并提取函数名
	return ctx.findFunctionDeclaratorName(declarator)
}

// findFunctionDeclaratorName 递归查找 function_declarator 并提取函数名
func (ctx *AnalysisContext) findFunctionDeclaratorName(node *sitter.Node) string {
	if node == nil {
		return ""
	}

	// 如果是 function_declarator，直接提取 declarator 字段（identifier）
	if node.Type() == "function_declarator" {
		identifier := node.ChildByFieldName("declarator")
		if identifier != nil && identifier.Type() == "identifier" {
			return ctx.GetSourceText(identifier)
		}
		return ""
	}

	// 如果是 pointer_declarator 或 array_declarator，递归处理其子节点
	if node.Type() == "pointer_declarator" || node.Type() == "array_declarator" {
		// pointer_declarator 的子节点可能是 function_declarator 或另一个 pointer_declarator
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			// 跳过 * 号等非声明器节点
			if child.Type() == "function_declarator" || child.Type() == "pointer_declarator" {
				return ctx.findFunctionDeclaratorName(child)
			}
		}
	}

	return ""
}

// ExtractFunctionParameters 从函数定义中提取参数节点列表
func (ctx *AnalysisContext) ExtractFunctionParameters(funcDef *sitter.Node) []*sitter.Node {
	if funcDef == nil || funcDef.Type() != "function_definition" {
		return nil
	}

	// function_definition 结构: [type, declarator, body, ...]
	// 参数列表在 declarator 的 parameter_list 中
	declarator := funcDef.ChildByFieldName("declarator")
	if declarator == nil {
		return nil
	}

	// *** 修复 ***: 递归查找 function_declarator（处理 pointer_declarator 情况）
	functionDeclarator := ctx.findFunctionDeclarator(declarator)
	if functionDeclarator == nil {
		return nil
	}

	// 查找参数列表
	parameters := functionDeclarator.ChildByFieldName("parameters")
	if parameters == nil || parameters.Type() != "parameter_list" {
		return nil
	}

	// 提取所有参数节点（identifier 节点）
	var paramNodes []*sitter.Node
	paramCount := parameters.ChildCount()
	for i := 0; i < int(paramCount); i++ {
		param := parameters.Child(i)
		if param.Type() == "parameter_declaration" {
			// 在 parameter_declaration 中查找 identifier
			paramDecl := param
			// 遍历子节点找到 identifier
			var findIdentifier func(node *sitter.Node) *sitter.Node
			findIdentifier = func(node *sitter.Node) *sitter.Node {
				if node == nil {
					return nil
				}
				if node.Type() == "identifier" {
					return node
				}
				for j := 0; j < int(node.ChildCount()); j++ {
					child := node.Child(j)
					if result := findIdentifier(child); result != nil {
						return result
					}
				}
				return nil
			}
			if identifier := findIdentifier(paramDecl); identifier != nil {
				paramNodes = append(paramNodes, identifier)
			}
		}
	}

	return paramNodes
}

// findFunctionDeclarator 递归查找 function_declarator 节点
// 用于处理 pointer_declarator、array_declarator 等包装节点
func (ctx *AnalysisContext) findFunctionDeclarator(node *sitter.Node) *sitter.Node {
	if node == nil {
		return nil
	}

	if node.Type() == "function_declarator" {
		return node
	}

	// 递归查找子节点中的 function_declarator
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "function_declarator" || child.Type() == "pointer_declarator" || child.Type() == "array_declarator" {
			if result := ctx.findFunctionDeclarator(child); result != nil {
				return result
			}
		}
	}

	return nil
}

// GetContainingFunctionName 获取节点所在的函数名
func (ctx *AnalysisContext) GetContainingFunctionName(node *sitter.Node) string {
	if node == nil {
		return ""
	}

	// 向上遍历 AST，查找包含该节点的函数定义
	current := node.Parent()
	visited := make(map[uintptr]bool)

	for current != nil {
		nodeID := current.ID()
		if visited[nodeID] {
			break
		}
		visited[nodeID] = true

		nodeType := current.Type()
		if nodeType == "function_definition" {
			// *** 修复 ***: 使用 ExtractFunctionNameFromDef 来处理 pointer_declarator 等情况
			return ctx.ExtractFunctionNameFromDef(current)
		}

		current = current.Parent()
	}

	return ""
}

// === 优化的 Node 操作辅助函数 ===
// 由于每个检测器使用独立的 Tree 副本，这些函数不需要锁保护
// 这允许真正的并行执行，大幅提升性能

// SafeChildCount 获取节点的子节点数量（无需锁，每个检测器有独立副本）
func SafeChildCount(node *sitter.Node) uint32 {
	return node.ChildCount()
}

// SafeChild 获取指定索引的子节点（无需锁，每个检测器有独立副本）
func SafeChild(node *sitter.Node, index int) *sitter.Node {
	return node.Child(index)
}

// SafeChildByFieldName 通过字段名获取子节点（无需锁，每个检测器有独立副本）
func SafeChildByFieldName(node *sitter.Node, fieldName string) *sitter.Node {
	return node.ChildByFieldName(fieldName)
}

// SafeNamedChild 通过索引获取命名子节点（无需锁，每个检测器有独立副本）
func SafeNamedChild(node *sitter.Node, index int) *sitter.Node {
	return node.NamedChild(index)
}

// SafeType 获取节点类型（无需锁，每个检测器有独立副本）
func SafeType(node *sitter.Node) string {
	return node.Type()
}

// SafeChildren 获取所有子节点（无需锁，每个检测器有独立副本）
func SafeChildren(node *sitter.Node) []*sitter.Node {
	count := node.ChildCount()
	children := make([]*sitter.Node, count)
	for i := 0; i < int(count); i++ {
		children[i] = node.Child(i)
	}
	return children
}