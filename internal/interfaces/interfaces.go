package interfaces

import (
	"context"
	"time"
)

// Detector 检测器接口
type Detector interface {
	Name() string
	Run(ctx *AnalysisContext) ([]Vulnerability, error)
}

// Vulnerability 漏洞结构
type Vulnerability struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Confidence string `json:"confidence"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
}

// AnalysisContext 分析上下文接口
type AnalysisContext interface {
	GetUnit() *ParsedUnit
	GetCFG() *CFG
	GetSymbolResolver() *SymbolResolver
}

// ParsedUnit 解析单元接口
type ParsedUnit interface {
	GetFilePath() string
	GetSource() []byte
	GetTree() *sitter.Tree
}

// CFG 控制流图接口
type CFG interface {
	GetEntry() *CFGNode
	GetNodes() []*CFGNode
}

// CFGNode CFG节点接口
type CFGNode interface {
	GetID() int
	GetASTNode() *sitter.Node
}

// SymbolResolver 符号解析器接口
type SymbolResolver interface {
	ResolveFunctionCall(calleeName, callerFile string) *Symbol
	GetFileCache() *FileCache
}

// Symbol 符号结构
type Symbol struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	FilePath   string `json:"file_path"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Signature  string `json:"signature"`
}

// FileCache 文件缓存接口
type FileCache interface {
	Get(filePath string) (*ParseUnit, error)
	GetStats() map[string]interface{}
}
