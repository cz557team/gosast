package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// JSONReport JSON 格式报告
type JSONReport struct {
	GeneratedAt   time.Time              `json:"generated_at"`
	Tool          ToolInfo               `json:"tool"`
	Summary       Summary                `json:"summary"`
	Vulnerabilities []VulnerabilityReport `json:"vulnerabilities"`
	Statistics    map[string]interface{} `json:"statistics,omitempty"`
}

// ToolInfo 工具信息
type ToolInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// Summary 漏洞统计摘要
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
	FilesScanned int          `json:"files_scanned,omitempty"`
}

// VulnerabilityReport 漏洞报告结构
type VulnerabilityReport struct {
	ID          string            `json:"id,omitempty"`
	Type        string            `json:"type"`
	CWE         string            `json:"cwe,omitempty"`
	Message     string            `json:"message"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Column      int               `json:"column"`
	Severity    string            `json:"severity"`
	Confidence  string            `json:"confidence"`
	Source      string            `json:"source,omitempty"`
	CodeSnippet string            `json:"code_snippet,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// JSONWriter JSON 报告写入器
type JSONWriter struct {
	writer    io.Writer
	pretty    bool
	includeCode bool
}

// NewJSONWriter 创建新的 JSON 写入器
func NewJSONWriter(writer io.Writer, options ...JSONOption) *JSONWriter {
	w := &JSONWriter{
		writer:      writer,
		pretty:      false,
		includeCode: false,
	}

	for _, opt := range options {
		opt(w)
	}

	return w
}

// JSONOption JSON 选项
type JSONOption func(*JSONWriter)

// WithPrettyJSON 启用美化 JSON 输出
func WithPrettyJSON() JSONOption {
	return func(w *JSONWriter) {
		w.pretty = true
	}
}

// WithCodeSnippet 包含代码片段
func WithCodeSnippet() JSONOption {
	return func(w *JSONWriter) {
		w.includeCode = true
	}
}

// Write 生成并写入报告
func (w *JSONWriter) Write(result *ScanResult) error {
	report := w.generateReport(result)

	var data []byte
	var err error

	if w.pretty {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	_, err = w.writer.Write(data)
	return err
}

// WriteToFile 写入到文件
func (w *JSONWriter) WriteToFile(result *ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	writer := NewJSONWriter(file, w.options()...)
	return writer.Write(result)
}

// generateReport 生成报告数据
func (w *JSONWriter) generateReport(result *ScanResult) *JSONReport {
	report := &JSONReport{
		GeneratedAt:   time.Now(),
		Tool: ToolInfo{
			Name:        "GoSAST",
			Version:     "1.0.0",
			Description: "Go Static Application Security Testing",
		},
		Summary: Summary{
			Total:      len(result.Vulnerabilities),
			BySeverity: make(map[string]int),
			ByType:     make(map[string]int),
		},
		Vulnerabilities: make([]VulnerabilityReport, 0, len(result.Vulnerabilities)),
		Statistics:      make(map[string]interface{}),
	}

	// 统计漏洞
	for _, vuln := range result.Vulnerabilities {
		// 按严重性统计
		report.Summary.BySeverity[vuln.Severity]++

		// 按类型统计
		report.Summary.ByType[vuln.Type]++

		// 构建漏洞报告
		vulnReport := VulnerabilityReport{
			Type:       vuln.Type,
			CWE:        w.extractCWE(vuln.Type),
			Message:    vuln.Message,
			File:       vuln.File,
			Line:       vuln.Line,
			Column:     vuln.Column,
			Severity:   vuln.Severity,
			Confidence: vuln.Confidence,
			Source:     vuln.Source,
		}

		// 添加代码片段（如果启用）
		if w.includeCode && vuln.File != "" {
			if code, err := w.extractCodeSnippet(vuln.File, vuln.Line); err == nil {
				vulnReport.CodeSnippet = code
			}
		}

		report.Vulnerabilities = append(report.Vulnerabilities, vulnReport)
	}

	// 按严重性排序
	sort.Slice(report.Vulnerabilities, func(i, j int) bool {
		severityOrder := map[string]int{
			"critical": 0,
			"high":     1,
			"medium":   2,
			"low":      3,
		}
		si := severityOrder[report.Vulnerabilities[i].Severity]
		sj := severityOrder[report.Vulnerabilities[j].Severity]
		if si == sj {
			return report.Vulnerabilities[i].Line < report.Vulnerabilities[j].Line
		}
		return si < sj
	})

	// 添加统计信息
	report.Statistics["scan_duration"] = result.Duration.String()
	report.Statistics["files_scanned"] = result.FilesScanned
	report.Statistics["detectors_used"] = result.DetectorsUsed

	return report
}

// extractCWE 从类型中提取 CWE 编号
func (w *JSONWriter) extractCWE(typeName string) string {
	// 从类型名中提取 CWE 编号，例如 "CWE-120 Buffer Overflow" -> "CWE-120"
	if strings.Contains(typeName, "CWE-") {
		parts := strings.Split(typeName, " ")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return ""
}

// extractCodeSnippet 提取代码片段
func (w *JSONWriter) extractCodeSnippet(filename string, line int) (string, error) {
	// 简化实现：读取文件并提取指定行
	// 实际项目中可能需要更复杂的逻辑
	return "", fmt.Errorf("not implemented")
}

// options 获取选项
func (w *JSONWriter) options() []JSONOption {
	opts := []JSONOption{}
	if w.pretty {
		opts = append(opts, WithPrettyJSON())
	}
	if w.includeCode {
		opts = append(opts, WithCodeSnippet())
	}
	return opts
}

// ScanResult 扫描结果
type ScanResult struct {
	Vulnerabilities []Vulnerability
	Duration        time.Duration
	FilesScanned    int
	DetectorsUsed   []string
}

// Vulnerability 漏洞结构（与 scanner 中的定义保持一致）
type Vulnerability struct {
	Type       string
	Message    string
	File       string
	Line       int
	Column     int
	Confidence string
	Severity   string
	Source     string
}
