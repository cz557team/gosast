package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Format 报告格式类型
type Format string

const (
	FormatJSON   Format = "json"
	FormatText   Format = "text"
	FormatSARIF  Format = "sarif"
	FormatAll    Format = "all"
)

// Writer 报告写入器接口
type Writer interface {
	Write(result *ScanResult) error
	WriteToFile(result *ScanResult, filename string) error
}

// Manager 报告管理器
type Manager struct {
	format      Format
	outputDir   string
	timestamp   bool
	filename    string
	concurrency int
}

// ManagerOption 管理器选项
type ManagerOption func(*Manager)

// WithFormat 设置报告格式
func WithFormat(format Format) ManagerOption {
	return func(m *Manager) {
		m.format = format
	}
}

// WithOutputDir 设置输出目录
func WithOutputDir(dir string) ManagerOption {
	return func(m *Manager) {
		m.outputDir = dir
	}
}

// WithTimestamp 添加时间戳到文件名
func WithTimestamp() ManagerOption {
	return func(m *Manager) {
		m.timestamp = true
	}
}

// WithFilename 设置自定义文件名
func WithFilename(filename string) ManagerOption {
	return func(m *Manager) {
		m.filename = filename
	}
}

// WithConcurrency 设置并发数
func WithConcurrency(n int) ManagerOption {
	return func(m *Manager) {
		m.concurrency = n
	}
}

// NewManager 创建新的报告管理器
func NewManager(options ...ManagerOption) *Manager {
	m := &Manager{
		format:      FormatText,
		outputDir:   ".",
		timestamp:   false,
		concurrency: 1,
	}

	for _, opt := range options {
		opt(m)
	}

	return m
}

// CreateWriter 创建报告写入器
func (m *Manager) CreateWriter(format Format, writer io.Writer) (Writer, error) {
	switch format {
	case FormatJSON:
		return NewJSONWriter(writer), nil
	case FormatText:
		return NewTextWriter(writer), nil
	case FormatSARIF:
		return NewSARIFWriter(writer), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// Generate 生成报告
func (m *Manager) Generate(result *ScanResult) ([]string, error) {
	var outputFiles []string

	switch m.format {
	case FormatAll:
		// 生成所有格式
		formats := []Format{FormatJSON, FormatText, FormatSARIF}
		for _, format := range formats {
			files, err := m.generateSingleFormat(result, format)
			if err != nil {
				return nil, err
			}
			outputFiles = append(outputFiles, files...)
		}
	case FormatJSON, FormatText, FormatSARIF:
		files, err := m.generateSingleFormat(result, m.format)
		if err != nil {
			return nil, err
		}
		outputFiles = append(outputFiles, files...)
	default:
		return nil, fmt.Errorf("unsupported format: %s", m.format)
	}

	return outputFiles, nil
}

// generateSingleFormat 生成单个格式的报告
func (m *Manager) generateSingleFormat(result *ScanResult, format Format) ([]string, error) {
	var files []string

	// 生成输出目录
	if err := os.MkdirAll(m.outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// 生成文件名
	filename := m.generateFilename(format)

	// 创建文件
	filePath := filepath.Join(m.outputDir, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	// 创建写入器
	writer, err := m.CreateWriter(format, file)
	if err != nil {
		return nil, err
	}

	// 写入报告
	if err := writer.Write(result); err != nil {
		return nil, fmt.Errorf("failed to write %s report: %w", format, err)
	}

	files = append(files, filePath)

	return files, nil
}

// generateFilename 生成文件名
func (m *Manager) generateFilename(format Format) string {
	if m.filename != "" {
		return m.filename
	}

	// 获取时间戳
	timestamp := ""
	if m.timestamp {
		timestamp = time.Now().Format("20060102_150405")
	}

	// 基础名称
	baseName := "gosast_report"

	// 组合名称
	if timestamp != "" {
		return fmt.Sprintf("%s_%s.%s", baseName, timestamp, format)
	}

	return fmt.Sprintf("%s.%s", baseName, format)
}

// ParseFormat 解析格式字符串
func ParseFormat(formatStr string) (Format, error) {
	switch strings.ToLower(formatStr) {
	case "json":
		return FormatJSON, nil
	case "text":
		return FormatText, nil
	case "sarif":
		return FormatSARIF, nil
	case "all":
		return FormatAll, nil
	default:
		return "", fmt.Errorf("unsupported format: %s", formatStr)
	}
}

// SupportedFormats 获取支持的格式列表
func SupportedFormats() []Format {
	return []Format{FormatJSON, FormatText, FormatSARIF, FormatAll}
}

// FormatDescription 获取格式描述
func FormatDescription(format Format) string {
	descriptions := map[Format]string{
		FormatJSON:  "JSON format - Machine-readable output",
		FormatText:  "Text format - Human-readable console output",
		FormatSARIF: "SARIF format - Static Analysis Results Interchange Format",
		FormatAll:   "All formats - Generate reports in all supported formats",
	}

	if desc, ok := descriptions[format]; ok {
		return desc
	}

	return "Unknown format"
}
