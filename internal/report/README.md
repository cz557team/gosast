# Report Module - 报告模块

GoSAST 的报告模块提供多种格式的安全扫描结果输出，支持灵活的定制和扩展。

## 功能特性

### 支持的输出格式

1. **Text Format (默认)** - 人类可读的控制台输出
2. **JSON Format** - 机器可读的 JSON 输出
3. **SARIF Format** - 静态分析结果交换格式（支持导入 IDE 和 CI/CD）
4. **All Formats** - 同时生成所有格式的报告

### 核心组件

#### 1. Writer 接口
```go
type Writer interface {
    Write(result *ScanResult) error
    WriteToFile(result *ScanResult, filename string) error
}
```

#### 2. 报告管理器 (Manager)
统一管理报告生成，支持：
- 多格式输出
- 自定义输出目录
- 时间戳文件名
- 并发控制

#### 3. 专用报告写入器

##### JSON Writer (`json_writer.go`)
- 结构化 JSON 输出
- 支持美化格式
- 包含代码片段选项
- 完整的元数据支持

##### Text Writer (`text_writer.go`)
- 人类可读的文本格式
- 按严重性分组显示
- 支持详细统计信息
- 彩色输出支持（可选）

##### SARIF Writer (`sarif_writer.go`)
- 符合 SARIF 2.1.0 规范
- 支持导入 Visual Studio、VS Code、GitHub CodeQL
- 标准的漏洞信息格式

## 使用示例

### 基本使用

```go
// 创建扫描结果
result := &report.ScanResult{
    Vulnerabilities: []report.Vulnerability{
        {
            Type:      "CWE-120 Buffer Overflow",
            Message:   "Buffer overflow detected",
            File:      "test.c",
            Line:      10,
            Severity:  "high",
            Confidence: "high",
        },
    },
    Duration:      1 * time.Second,
    FilesScanned:  10,
    DetectorsUsed: []string{"Buffer Overflow Detector"},
}

// 创建 JSON 报告
writer := report.NewJSONWriter(os.Stdout, report.WithPrettyJSON())
err := writer.Write(result)
if err != nil {
    log.Fatal(err)
}
```

### 使用报告管理器

```go
// 创建管理器
mgr := report.NewManager(
    report.WithFormat(report.FormatJSON),
    report.WithOutputDir("./reports"),
    report.WithTimestamp(),
)

// 生成报告
files, err := mgr.Generate(result)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("报告已生成: %v\n", files)
```

### 命令行使用

```bash
# 文本格式输出（默认）
./scanner /path/to/code

# JSON 格式输出
./scanner -format json /path/to/code

# SARIF 格式输出
./scanner -format sarif /path/to/code

# 生成所有格式
./scanner -format all /path/to/code

# 指定输出目录
./scanner -format json -output-dir ./reports /path/to/code

# 添加时间戳
./scanner -format json -timestamp /path/to/code

# 列出支持的格式
./scanner --list-formats
```

## 命令行参数

- `-format <format>`: 输出格式 (text, json, sarif, all)
- `-output-dir <dir>`: 报告输出目录
- `-timestamp`: 在文件名中添加时间戳
- `--list-formats`: 列出支持的输出格式

## 报告格式详情

### JSON 格式结构

```json
{
  "generated_at": "2024-01-15T10:30:00Z",
  "tool": {
    "name": "GoSAST",
    "version": "1.0.0",
    "description": "Go Static Application Security Testing"
  },
  "summary": {
    "total": 5,
    "by_severity": {
      "critical": 2,
      "high": 2,
      "medium": 1
    },
    "by_type": {
      "CWE-120 Buffer Overflow": 2,
      "CWE-78 Command Injection": 1
    },
    "files_scanned": 10
  },
  "vulnerabilities": [
    {
      "type": "CWE-120 Buffer Overflow",
      "cwe": "CWE-120",
      "message": "Buffer overflow detected: string of 46 bytes copied to buffer of 10 bytes",
      "file": "test.c",
      "line": 10,
      "column": 5,
      "severity": "high",
      "confidence": "high",
      "code_snippet": "strcpy(buffer, \"This is a very long string\");"
    }
  ]
}
```

### SARIF 格式结构

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "GoSAST",
          "version": "1.0.0",
          "rules": [
            {
              "id": "CWE-120",
              "name": "Buffer Overflow",
              "shortDescription": { "text": "Buffer overflow detected" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CWE-120",
          "level": "error",
          "message": { "text": "Buffer overflow detected" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "test.c" },
                "region": { "startLine": 10 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## 扩展开发

### 添加新的输出格式

1. 创建新的写入器结构体，实现 `Writer` 接口
2. 在 `manager.go` 的 `CreateWriter` 方法中添加格式支持
3. 在 `ParseFormat` 函数中添加格式解析

```go
type MyCustomWriter struct {
    // 实现 Writer 接口
}

func (w *MyCustomWriter) Write(result *ScanResult) error {
    // 自定义实现
}

func (m *Manager) CreateWriter(format Format, writer io.Writer) (Writer, error) {
    switch format {
    case FormatMyCustom:
        return NewMyCustomWriter(writer), nil
    // ...
    }
}
```

### 自定义字段

可以通过 `Metadata` 字段添加自定义信息：

```go
vuln := report.Vulnerability{
    Type:      "CWE-120 Buffer Overflow",
    Message:   "Buffer overflow detected",
    // ...
    Metadata: map[string]interface{}{
        "custom_field": "custom_value",
        "score":        9.5,
    },
}
```

## 最佳实践

1. **选择合适的格式**：
   - 人类审查：使用 `text` 格式
   - 自动化处理：使用 `json` 格式
   - IDE 集成：使用 `sarif` 格式

2. **CI/CD 集成**：
   ```bash
   # 在 CI 中生成 SARIF 报告
   ./scanner -format sarif -output-dir ./reports
   ```

3. **报告存档**：
   ```bash
   # 带时间戳的报告
   ./scanner -format all -timestamp -output-dir ./reports/$(date +%Y%m%d)
   ```

## 性能考虑

- 大型项目建议使用文件输出而非控制台输出
- 使用并发控制避免资源竞争
- SARIF 格式在大型项目中性能较好

## 故障排除

### 常见问题

1. **权限错误**：确保输出目录有写权限
2. **格式错误**：使用 `--list-formats` 验证格式名称
3. **文件冲突**：启用 `-timestamp` 选项

### 调试

启用详细模式查看详细信息：

```bash
./scanner -v -format json /path/to/code
```
