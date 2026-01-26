package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SARIFWriter SARIF 格式报告写入器
type SARIFWriter struct {
	writer io.Writer
	pretty bool
}

// NewSARIFWriter 创建新的 SARIF 写入器
func NewSARIFWriter(writer io.Writer, options ...SARIFOption) *SARIFWriter {
	w := &SARIFWriter{
		writer: writer,
		pretty: false,
	}

	for _, opt := range options {
		opt(w)
	}

	return w
}

// SARIFOption SARIF 选项
type SARIFOption func(*SARIFWriter)

// WithPrettySARIF 启用美化 JSON 输出
func WithPrettySARIF() SARIFOption {
	return func(w *SARIFWriter) {
		w.pretty = true
	}
}

// Write 生成并写入 SARIF 报告
func (w *SARIFWriter) Write(result *ScanResult) error {
	sarifReport := w.generateSARIFReport(result)

	var data []byte
	var err error

	if w.pretty {
		data, err = json.MarshalIndent(sarifReport, "", "  ")
	} else {
		data, err = json.Marshal(sarifReport)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	_, err = w.writer.Write(data)
	return err
}

// WriteToFile 写入到文件
func (w *SARIFWriter) WriteToFile(result *ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	writer := NewSARIFWriter(file, w.options()...)
	return writer.Write(result)
}

// generateSARIFReport 生成 SARIF 报告
func (w *SARIFWriter) generateSARIFReport(result *ScanResult) *SARIF {
	// SARIF 2.1.0 规范
	sarif := &SARIF{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "GoSAST",
						Version:        "1.0.0",
						InformationURI: "https://github.com/gosast/gosast",
						Rules:          w.generateRules(result),
					},
				},
				Results: w.generateResults(result),
			},
		},
	}

	return sarif
}

// generateRules 生成规则定义
func (w *SARIFWriter) generateRules(result *ScanResult) []Rule {
	rules := make(map[string]Rule)

	for _, vuln := range result.Vulnerabilities {
		ruleID := w.extractCWE(vuln.Type)
		if ruleID == "" {
			ruleID = "SECURITY"
		}

		if _, exists := rules[ruleID]; !exists {
			rules[ruleID] = Rule{
				ID:               ruleID,
				Name:             vuln.Type,
				ShortDescription: Description{Text: vuln.Message},
				FullDescription:  Description{Text: fmt.Sprintf("Security vulnerability: %s", vuln.Type)},
				HelpURI:          fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(ruleID, "CWE-")),
			}
		}
	}

	// 转换为切片
	rulesSlice := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		rulesSlice = append(rulesSlice, rule)
	}

	return rulesSlice
}

// generateResults 生成结果
func (w *SARIFWriter) generateResults(result *ScanResult) []Result {
	results := make([]Result, 0, len(result.Vulnerabilities))

	for _, vuln := range result.Vulnerabilities {
		ruleID := w.extractCWE(vuln.Type)
		if ruleID == "" {
			ruleID = "SECURITY"
		}

		result := Result{
			RuleID:    ruleID,
			RuleIndex: w.getRuleIndex(ruleID, result),
			Level:     w.mapSeverityToSARIF(vuln.Severity),
			Message:   Message{Text: vuln.Message},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: vuln.File,
						},
						Region: Region{
							StartLine:   vuln.Line,
							StartColumn: vuln.Column,
						},
					},
				},
			},
		}

		// 添加属性
		result.Properties = map[string]interface{}{
			"confidence": vuln.Confidence,
			"source":     vuln.Source,
		}

		results = append(results, result)
	}

	return results
}

// getRuleIndex 获取规则索引
func (w *SARIFWriter) getRuleIndex(ruleID string, result *ScanResult) int {
	// 简化的实现：实际需要维护规则列表和索引
	return 0
}

// extractCWE 提取 CWE 编号
func (w *SARIFWriter) extractCWE(typeName string) string {
	if typeName == "" {
		return ""
	}
	
	parts := strings.Split(typeName, " ")
	if len(parts) > 0 {
		if strings.HasPrefix(parts[0], "CWE-") {
			return parts[0]
		}
	}
	return ""
}

// mapSeverityToSARIF 映射严重性到 SARIF 级别
func (w *SARIFWriter) mapSeverityToSARIF(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// options 获取选项
func (w *SARIFWriter) options() []SARIFOption {
	opts := []SARIFOption{}
	if w.pretty {
		opts = append(opts, WithPrettySARIF())
	}
	return opts
}

// SARIF SARIF 报告结构
type SARIF struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run SARIF 运行
type Run struct {
	Tool   Tool    `json:"tool"`
	Results []Result `json:"results"`
}

// Tool SARIF 工具
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver 工具驱动
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

// Rule SARIF 规则
type Rule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	ShortDescription Description `json:"shortDescription"`
	FullDescription  Description `json:"fullDescription"`
	HelpURI          string     `json:"helpUri,omitempty"`
}

// Description 描述
type Description struct {
	Text string `json:"text"`
}

// Result SARIF 结果
type Result struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex,omitempty"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// Message 消息
type Message struct {
	Text string `json:"text"`
}

// Location 位置
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation,omitempty"`
}

// PhysicalLocation 物理位置
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region,omitempty"`
}

// ArtifactLocation artifact 位置
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region 区域
type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}
