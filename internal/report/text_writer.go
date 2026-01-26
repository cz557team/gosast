package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// TextWriter 文本格式报告写入器
type TextWriter struct {
	writer      io.Writer
	verbose     bool
	showColor   bool
	showStats   bool
}

// NewTextWriter 创建新的文本写入器
func NewTextWriter(writer io.Writer, options ...TextOption) *TextWriter {
	w := &TextWriter{
		writer:    writer,
		verbose:   false,
		showColor: false,
		showStats: true,
	}

	for _, opt := range options {
		opt(w)
	}

	return w
}

// TextOption 文本选项
type TextOption func(*TextWriter)

// WithVerbose 启用详细输出
func WithVerbose() TextOption {
	return func(w *TextWriter) {
		w.verbose = true
	}
}

// WithColor 启用彩色输出
func WithColor() TextOption {
	return func(w *TextWriter) {
		w.showColor = true
	}
}

// WithoutStats 禁用统计信息
func WithoutStats() TextOption {
	return func(w *TextWriter) {
		w.showStats = false
	}
}

// Write 生成并写入文本报告
func (w *TextWriter) Write(result *ScanResult) error {
	// 如果没有漏洞
	if len(result.Vulnerabilities) == 0 {
		w.writeNoVulnerabilities(result)
		return nil
	}

	// 写入标题
	w.writeHeader(result)

	// 写入统计信息
	if w.showStats {
		w.writeStatistics(result)
	}

	// 写入漏洞详情
	w.writeVulnerabilities(result)

	return nil
}

// WriteToFile 写入到文件
func (w *TextWriter) WriteToFile(result *ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	writer := NewTextWriter(file, w.options()...)
	return writer.Write(result)
}

// writeHeader 写入报告标题
func (w *TextWriter) writeHeader(result *ScanResult) {
	fmt.Fprintf(w.writer, "\n")
	fmt.Fprintf(w.writer, "GoSAST Security Scan Results\n")
	fmt.Fprintf(w.writer, "=============================\n")
	fmt.Fprintf(w.writer, "Scan Time: %s\n", result.Duration)
	fmt.Fprintf(w.writer, "Generated: %s\n\n", time.Now().Format(time.RFC3339))
}

// writeNoVulnerabilities 写入无漏洞信息
func (w *TextWriter) writeNoVulnerabilities(result *ScanResult) {
	fmt.Fprintf(w.writer, "\n✓ No vulnerabilities found.\n\n")
	fmt.Fprintf(w.writer, "Scan Summary:\n")
	fmt.Fprintf(w.writer, "  Files scanned: %d\n", result.FilesScanned)
	fmt.Fprintf(w.writer, "  Duration: %s\n", result.Duration)
	fmt.Fprintf(w.writer, "  Detectors used: %d\n\n", len(result.DetectorsUsed))
}

// writeStatistics 写入统计信息
func (w *TextWriter) writeStatistics(result *ScanResult) {
	// 按严重性统计
	severityCount := make(map[string]int)
	for _, vuln := range result.Vulnerabilities {
		severityCount[vuln.Severity]++
	}

	fmt.Fprintf(w.writer, "Summary:\n")
	fmt.Fprintf(w.writer, "--------\n")
	fmt.Fprintf(w.writer, "Total vulnerabilities: %d\n", len(result.Vulnerabilities))
	fmt.Fprintf(w.writer, "  Critical: %d\n", severityCount["critical"])
	fmt.Fprintf(w.writer, "  High: %d\n", severityCount["high"])
	fmt.Fprintf(w.writer, "  Medium: %d\n", severityCount["medium"])
	fmt.Fprintf(w.writer, "  Low: %d\n\n", severityCount["low"])

	// 按类型统计
	typeCount := make(map[string]int)
	for _, vuln := range result.Vulnerabilities {
		typeCount[vuln.Type]++
	}

	if w.verbose {
		fmt.Fprintf(w.writer, "By Type:\n")
		for vtype, count := range typeCount {
			fmt.Fprintf(w.writer, "  %s: %d\n", vtype, count)
		}
		fmt.Fprintf(w.writer, "\n")
	}

	// 文件统计
	fileCount := make(map[string]int)
	for _, vuln := range result.Vulnerabilities {
		fileCount[vuln.File]++
	}

	fmt.Fprintf(w.writer, "Files with issues: %d\n\n", len(fileCount))

	// 检测器统计
	fmt.Fprintf(w.writer, "Detectors used: %d\n", len(result.DetectorsUsed))
	for _, detector := range result.DetectorsUsed {
		fmt.Fprintf(w.writer, "  - %s\n", detector)
	}
	fmt.Fprintf(w.writer, "\n")
}

// writeVulnerabilities 写入漏洞详情
func (w *TextWriter) writeVulnerabilities(result *ScanResult) {
	// 按严重性分组
	groups := make(map[string][]Vulnerability)
	for _, vuln := range result.Vulnerabilities {
		groups[vuln.Severity] = append(groups[vuln.Severity], vuln)
	}

	// 按严重性顺序输出
	severityOrder := []string{"critical", "high", "medium", "low"}

	for _, severity := range severityOrder {
		vulns, ok := groups[severity]
		if !ok || len(vulns) == 0 {
			continue
		}

		// 按文件分组
		fileGroups := make(map[string][]Vulnerability)
		for _, vuln := range vulns {
			fileGroups[vuln.File] = append(fileGroups[vuln.File], vuln)
		}

		// 输出分组
		fmt.Fprintf(w.writer, "%s Vulnerabilities (%d):\n", strings.ToUpper(severity), len(vulns))
		fmt.Fprintf(w.writer, "%s\n", strings.Repeat("=", 50))

		for filename, fileVulns := range fileGroups {
			fmt.Fprintf(w.writer, "\nFile: %s\n", filename)
			fmt.Fprintf(w.writer, "%s\n", strings.Repeat("-", 50))

			// 使用 tabwriter 格式化输出
			tw := tabwriter.NewWriter(w.writer, 0, 8, 2, ' ', 0)
			for _, vuln := range fileVulns {
				fmt.Fprintf(tw, "  %s\t%d:%d\t%s\t(%s)\n",
					severity,
					vuln.Line,
					vuln.Column,
					vuln.Message,
					vuln.Confidence,
				)
				if w.verbose && vuln.Source != "" {
					fmt.Fprintf(tw, "  \t\tSource: %s\n", vuln.Source)
				}
			}
			tw.Flush()
		}
		fmt.Fprintf(w.writer, "\n")
	}
}

// options 获取选项
func (w *TextWriter) options() []TextOption {
	opts := []TextOption{}
	if w.verbose {
		opts = append(opts, WithVerbose())
	}
	if w.showColor {
		opts = append(opts, WithColor())
	}
	return opts
}
