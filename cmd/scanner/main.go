package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"gosast/internal/core"
	"gosast/internal/detectors"
	"gosast/internal/report"
)

// getExcludedDirs 返回统一的排除目录列表
// 【修复】项目规模检测和实际扫描使用相同的排除列表
func getExcludedDirs() map[string]bool {
	return map[string]bool{
		// 构建产物
		"build": true, "dist": true, "target": true, "cmake-build": true, ".cmake": true,
		// 依赖管理
		"vendor": true, "node_modules": true, "third_party": true, "thirdparty": true,
		"3rdparty": true, "deps": true, "dependency": true,
		"libraries": true, "lib": true, "external": true, "externals": true,
		// 版本控制
		".git": true, ".svn": true, ".hg": true,
		// IDE 和编辑器
		".cache": true, ".idea": true, ".vscode": true,
		// Python 缓存
		"__pycache__": true, ".pytest_cache": true,
		// 测试代码
		"test": true, "tests": true, "testing": true, "fuzz": true,
		// 示例和文档
		"example": true, "examples": true, "sample": true, "samples": true,
		"demo": true, "demos": true,
		"scripts": true, "doc": true, "docs": true,
		"config": true,
	}
}

// Vulnerability 表示一个安全漏洞
type Vulnerability struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Confidence string `json:"confidence"`
	Severity   string `json:"severity"`
	Source     string `json:"source"` // 污染源（可选）
}

// Scanner 主扫描器
type Scanner struct {
	detectors       []core.Detector          // 原始检测器列表（用于获取检测器信息）
	detectorPools   map[string][]core.Detector // 【方案B】检测器池：detectorName -> []Detector（每个worker一个实例）
	detectorMutexes map[int]*sync.Mutex      // 保留（用于向后兼容，但不再使用）
	arrayCollector  *core.GlobalArrayCollector // 全局数组收集器
	structCollector *core.GlobalStructCollector // V13: 全局结构体收集器
	// 【Phase 5 优化】CFG 缓存：filePath -> CFG，避免跨文件分析重复构建
	cfgCache        map[string]*core.CFG
	cfgCacheMu      sync.RWMutex
	workers           int
	verbose           bool
	outputFormat      report.Format
	outputFile        string
	timestamp         bool
	disableTimeout    bool // 【调试】禁用超时保护
	// 性能统计
	detectorTimings   map[string]time.Duration // 检测器耗时统计
	detectorTimingsMu sync.RWMutex
	// Phase 5: 自动配置参数
	batchSize    int    // 分批扫描大小（0 = 不分批）
	projectScale string // 项目规模标识
}

// NewScanner 创建新的扫描器
func NewScanner(workers int, verbose bool, outputFormat report.Format, outputFile string, timestamp bool) *Scanner {
	return &Scanner{
		detectors:       make([]core.Detector, 0),
		detectorPools:   make(map[string][]core.Detector), // 【方案B】初始化检测器池
		detectorMutexes: make(map[int]*sync.Mutex),         // 保留（用于向后兼容，但不再使用）
		arrayCollector:  core.NewGlobalArrayCollector(),
		structCollector: core.NewGlobalStructCollector(), // V13
		workers:         workers,
		verbose:         verbose,
		outputFormat:    outputFormat,
		outputFile:      outputFile,
		timestamp:       timestamp,
		detectorTimings: make(map[string]time.Duration),
		batchSize:       0,            // 默认不分批
		projectScale:    "unknown",
		cfgCache:        make(map[string]*core.CFG), // 【Phase 5】CFG 缓存初始化
	}
}

// SetAutoConfig 设置自动配置参数（Phase 5）
func (s *Scanner) SetAutoConfig(batchSize int, scale string) {
	s.batchSize = batchSize
	s.projectScale = scale
}

// AddDetector 添加检测器（保存模板，稍后创建池）
func (s *Scanner) AddDetector(detector core.Detector) {
	s.detectors = append(s.detectors, detector)
	// detectorMutexes 保留但不使用（向后兼容）
}

// FinalizeDetectors 完成检测器初始化，为每个worker创建独立的detector实例
// 【方案B】必须在所有 AddDetector 调用完成后执行
func (s *Scanner) FinalizeDetectors() error {
	s.detectorPools = make(map[string][]core.Detector)

	// 为每个 worker 创建独立的 detector 实例
	for _, templateDetector := range s.detectors {
		detectorName := templateDetector.Name()
		pool := make([]core.Detector, s.workers)

		for w := 0; w < s.workers; w++ {
			// 创建新的 detector 实例
			// 注意：这里需要根据 detector 类型调用相应的构造函数
			// 由于 Go 的类型系统限制，我们使用反射
			newDetector, err := s.cloneDetector(templateDetector)
			if err != nil {
				return fmt.Errorf("failed to clone detector %s: %w", detectorName, err)
			}
			pool[w] = newDetector
		}

		s.detectorPools[detectorName] = pool
	}

	return nil
}

// cloneDetector 使用反射创建 detector 的副本（深拷贝 map 字段）
// 使用 unsafe 包来访问不可导出字段（如小写的 map 字段）
func (s *Scanner) cloneDetector(template core.Detector) (core.Detector, error) {
	// 获取 detector 的具体类型
	detectorType := reflect.TypeOf(template)

	// 创建新实例
	newValue := reflect.New(detectorType.Elem())

	// 深拷贝字段值
	templateValue := reflect.ValueOf(template).Elem()
	targetValue := newValue.Elem()

	for i := 0; i < templateValue.NumField(); i++ {
		field := templateValue.Field(i)
		targetField := targetValue.Field(i)

		// 使用 unsafe 来访问不可导出字段
		if !field.CanInterface() {
			// 不可导出字段，使用 unsafe 直接复制指针
			// 注意：这会导致字段共享，但对于 map 类型我们需要深拷贝
			fieldPtr := unsafe.Pointer(field.UnsafeAddr())
			targetFieldPtr := unsafe.Pointer(targetField.UnsafeAddr())

			// 获取字段类型
			fieldType := detectorType.Elem().Field(i)

			// 如果是 map 类型，需要创建新的 map
			if fieldType.Type.Kind() == reflect.Map {
				// 使用 reflect.NewAt 创建可访问的 reflect.Value
				mapValue := reflect.NewAt(fieldType.Type, fieldPtr).Elem()
				targetMapValue := reflect.NewAt(fieldType.Type, targetFieldPtr).Elem()

				// 创建新的 map
				newMap := reflect.MakeMap(fieldType.Type)
				if !mapValue.IsNil() {
					for _, key := range mapValue.MapKeys() {
						value := mapValue.MapIndex(key)
						newMap.SetMapIndex(key, value)
					}
				}
				targetMapValue.Set(newMap)
			} else {
				// 非 map 类型，直接复制内存
				size := fieldType.Type.Size()
				for j := uintptr(0); j < size; j++ {
					*(*byte)(unsafe.Pointer(uintptr(targetFieldPtr) + j)) = *(*byte)(unsafe.Pointer(uintptr(fieldPtr) + j))
				}
			}
			continue
		}

		// 可导出字段的处理
		// 处理 map 类型：需要深拷贝
		if field.Kind() == reflect.Map {
			// 创建新的 map（即使原 map 是 nil，也创建空 map）
			newMap := reflect.MakeMap(field.Type())

			// 如果原 map 不是 nil，复制所有键值对
			if !field.IsNil() {
				for _, key := range field.MapKeys() {
					value := field.MapIndex(key)
					newMap.SetMapIndex(key, value)
				}
			}
			targetField.Set(newMap)
		} else {
			// 非 map 类型直接复制
			targetField.Set(field)
		}
	}

	// 返回新实例
	return newValue.Interface().(core.Detector), nil
}

// recordDetectorTiming 记录检测器耗时
func (s *Scanner) recordDetectorTiming(detectorName string, duration time.Duration) {
	s.detectorTimingsMu.Lock()
	defer s.detectorTimingsMu.Unlock()
	s.detectorTimings[detectorName] += duration
}

// printDetectorTimings 打印检测器耗时统计
func (s *Scanner) printDetectorTimings() {
	s.detectorTimingsMu.RLock()
	defer s.detectorTimingsMu.RUnlock()

	if len(s.detectorTimings) == 0 {
		return
	}

	log.Printf("\n=== 检测器耗时统计 ===")

	// 按耗时排序
	type timing struct {
		name     string
		duration time.Duration
	}
	var timings []timing
	for name, duration := range s.detectorTimings {
		timings = append(timings, timing{name, duration})
	}

	// 简单冒泡排序
	for i := 0; i < len(timings); i++ {
		for j := i + 1; j < len(timings); j++ {
			if timings[j].duration > timings[i].duration {
				timings[i], timings[j] = timings[j], timings[i]
			}
		}
	}

	total := time.Duration(0)
	for _, t := range timings {
		total += t.duration
	}

	for _, t := range timings {
		pct := float64(t.duration) / float64(total) * 100
		log.Printf("  %-30s %12v  (%5.1f%%)", t.name, t.duration, pct)
	}
	log.Printf("  %-30s %12v", "总计", total)
	log.Printf("====================\n")
}

// getDetectorIndex 根据检测器名称查找其在原始 detectors 切片中的索引
func (s *Scanner) getDetectorIndex(name string) int {
	for i, det := range s.detectors {
		if det.Name() == name {
			return i
		}
	}
	return -1
}

// ScanFile 扫描单个文件
// 【方案B】workerID 参数用于从检测器池中获取独立的 detector 实例
func (s *Scanner) ScanFile(ctx context.Context, filePath string, workerID int) ([]Vulnerability, error) {
	fileStart := time.Now()

	// 解析文件
	parseStart := time.Now()
	unit, err := core.ParseFile(ctx, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
	}
	parseDuration := time.Since(parseStart)

	// 【Phase 5 优化】构建并缓存原始 CFG，供跨文件分析复用
	cfgStart := time.Now()
	// 使用读锁检查缓存是否已存在
	s.cfgCacheMu.RLock()
	if _, exists := s.cfgCache[filePath]; !exists {
		s.cfgCacheMu.RUnlock()
		// 缓存不存在，构建 CFG 并缓存
		originalCFG, err := core.BuildCFG(unit)
		if err != nil {
			if s.verbose {
				log.Printf("Warning: failed to build CFG for cache %s: %v", filePath, err)
			}
		} else {
			s.cfgCacheMu.Lock()
			s.cfgCache[filePath] = originalCFG
			s.cfgCacheMu.Unlock()
		}
	} else {
		s.cfgCacheMu.RUnlock()
	}
	cfgDuration := time.Since(cfgStart)

	// 【超时诊断】如果解析或CFG构建时间过长，记录日志
	if parseDuration > 5*time.Second {
		log.Printf("[超时诊断] %s 解析耗时: %v", filePath, parseDuration)
	}
	if cfgDuration > 5*time.Second {
		log.Printf("[超时诊断] %s CFG构建耗时: %v", filePath, cfgDuration)
	}

	// 获取全局数组信息（预扫描阶段收集）
	globalArrays := s.arrayCollector.GetKnownArrays()

	// V13: 获取全局结构体信息（预扫描阶段收集）
	globalStructs := s.structCollector.GetStructs()

	// 【方案B】从检测器池中获取该 worker 专用的 detector 实例
	workerDetectors := make([]core.Detector, len(s.detectors))
	for i, templateDetector := range s.detectors {
		detectorName := templateDetector.Name()
		pool, ok := s.detectorPools[detectorName]
		if !ok || len(pool) == 0 {
			return nil, fmt.Errorf("detector pool not initialized for %s", detectorName)
		}
		// 使用 workerID 从池中获取对应的 detector 实例
		workerDetectors[i] = pool[workerID%len(pool)]
	}

	// *** 性能优化：双层并行架构 ***
	// 快速检测器串行执行，慢速检测器并发执行
	var allVulns []Vulnerability

	// 分类检测器
	var fastDetectors []core.Detector
	var slowDetectors []core.Detector
	slowDetectorNames := map[string]bool{
		"Integer Overflow Detector": true,
		"Heap Overflow":           true,
	}

	for _, detector := range workerDetectors {
		if slowDetectorNames[detector.Name()] {
			slowDetectors = append(slowDetectors, detector)
		} else {
			fastDetectors = append(fastDetectors, detector)
		}
	}

	// 第一阶段：串行执行快速检测器
	// 【方案B】无需锁，因为每个 worker 使用独立的 detector 实例
	for _, detector := range fastDetectors {
		detectorName := detector.Name()
		detectorStart := time.Now()

		// 为每个检测器创建完全独立的分析上下文（克隆 Tree 和 CFG）
		clonedUnit := unit.Copy()
		detectorCtx := core.NewAnalysisContext(clonedUnit)

		// 为每个检测器独立构建 CFG（基于克隆的 Tree）
		clonedCFG, err := core.BuildCFG(clonedUnit)
		if err != nil {
			if s.verbose {
				log.Printf("Warning: failed to build CFG for detector %s: %v", detector.Name(), err)
			}
			clonedCFG = core.NewCFG()
		}
		detectorCtx.CFG = clonedCFG

		// 创建全局数组和结构体 map 的副本，避免并发访问
		detectorCtx.GlobalArrays = make(map[string]bool)
		for k, v := range globalArrays {
			detectorCtx.GlobalArrays[k] = v
		}
		detectorCtx.GlobalStructs = make(map[string]*core.StructInfo)
		for k, v := range globalStructs {
			// 深拷贝 StructInfo（因为它包含 Fields map）
			structCopy := &core.StructInfo{
				Name:     v.Name,
				FilePath: v.FilePath,
				Line:     v.Line,
				Fields:   make(map[string]*core.StructFieldInfo),
			}
			for fieldName, fieldInfo := range v.Fields {
				structCopy.Fields[fieldName] = fieldInfo
			}
			detectorCtx.GlobalStructs[k] = structCopy
		}

		detectorVulns, err := detector.Run(detectorCtx)
		detectorDuration := time.Since(detectorStart)

		// 【超时诊断】记录检测器完成和耗时
		if detectorDuration > 10*time.Second {
			log.Printf("[超时诊断] %s 检测器 %s 耗时: %v", filePath, detectorName, detectorDuration)
		}

		s.recordDetectorTiming(detector.Name(), detectorDuration)

		if err != nil {
			if s.verbose {
				log.Printf("Detector %s failed on %s: %v", detector.Name(), filePath, err)
			}
			continue
		}

		// 转换为标准格式
		for _, v := range detectorVulns {
			allVulns = append(allVulns, Vulnerability{
				Type:       v.Type,
				Message:    v.Message,
				File:       filePath,
				Line:       v.Line,
				Column:     v.Column,
				Confidence: v.Confidence,
				Severity:   v.Severity,
				Source:     v.Source,
			})
		}
	}

	// 第二阶段：并发执行慢速检测器 (Integer Overflow + Heap Overflow)
	// 【方案B】无需锁，因为每个 worker 使用独立的 detector 实例
	if len(slowDetectors) > 0 {
		var wg sync.WaitGroup
		var slowVulnsMu sync.Mutex
		slowVulns := make([][]core.DetectorVulnerability, len(slowDetectors))

		for i, detector := range slowDetectors {
			wg.Add(1)
			go func(detIdx int, det core.Detector) {
				defer wg.Done()

				detectorName := det.Name()
				detectorStart := time.Now()

				// 【方案B】移除 Scanner 层锁，每个 worker 有独立实例

				// 为每个检测器创建完全独立的分析上下文（克隆 Tree 和 CFG）
				clonedUnit := unit.Copy()
				detectorCtx := core.NewAnalysisContext(clonedUnit)

				// 为每个检测器独立构建 CFG（基于克隆的 Tree）
				clonedCFG, err := core.BuildCFG(clonedUnit)
				if err != nil {
					if s.verbose {
						log.Printf("Warning: failed to build CFG for detector %s: %v", det.Name(), err)
					}
					clonedCFG = core.NewCFG()
				}
				detectorCtx.CFG = clonedCFG

				// 创建全局数组和结构体 map 的副本，避免并发访问
				detectorCtx.GlobalArrays = make(map[string]bool)
				for k, v := range globalArrays {
					detectorCtx.GlobalArrays[k] = v
				}
				detectorCtx.GlobalStructs = make(map[string]*core.StructInfo)
				for k, v := range globalStructs {
					// 深拷贝 StructInfo（因为它包含 Fields map）
					structCopy := &core.StructInfo{
						Name:     v.Name,
						FilePath: v.FilePath,
						Line:     v.Line,
						Fields:   make(map[string]*core.StructFieldInfo),
					}
					for fieldName, fieldInfo := range v.Fields {
						structCopy.Fields[fieldName] = fieldInfo
					}
					detectorCtx.GlobalStructs[k] = structCopy
				}

				detectorVulns, err := det.Run(detectorCtx)
				detectorDuration := time.Since(detectorStart)

				// 【超时诊断】记录检测器完成和耗时
				if detectorDuration > 20*time.Second {
					log.Printf("[超时诊断] %s 慢速检测器 %s 耗时: %v", filePath, detectorName, detectorDuration)
				}

				// 记录检测器耗时
				s.recordDetectorTiming(det.Name(), detectorDuration)

				if err != nil {
					if s.verbose {
						log.Printf("Detector %s failed on %s: %v", det.Name(), filePath, err)
					}
					return
				}

				// 使用互斥锁保护结果收集
				slowVulnsMu.Lock()
				slowVulns[detIdx] = detectorVulns
				slowVulnsMu.Unlock()
			}(i, detector)
		}

		// 等待所有慢速检测器完成
		wg.Wait()

		// 合并慢速检测器的结果
		for _, detectorVulns := range slowVulns {
			for _, v := range detectorVulns {
				allVulns = append(allVulns, Vulnerability{
					Type:       v.Type,
					Message:    v.Message,
					File:       filePath,
					Line:       v.Line,
					Column:     v.Column,
					Confidence: v.Confidence,
					Severity:   v.Severity,
					Source:     v.Source,
				})
			}
		}
	}

	// 【超时诊断】记录文件总扫描时间
	totalDuration := time.Since(fileStart)
	if totalDuration > 30*time.Second {
		log.Printf("[超时诊断] %s 总扫描耗时: %v (解析:%v CFG:%v)", filePath, totalDuration, parseDuration, cfgDuration)
	}

	return allVulns, nil
}

// ScanDir 扫描整个工程目录
func (s *Scanner) ScanDir(ctx context.Context, dirPath string) ([]Vulnerability, int, error) {
	var files []string
	var mutex sync.Mutex
	var totalFiles, scannedFiles int

	// 【修复】使用统一的排除目录列表
	excludedDirs := getExcludedDirs()

	// 【修复】重要信息始终显示
	log.Printf("开始扫描目录: %s", dirPath)


	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 获取相对路径用于目录过滤
		relPath, err := filepath.Rel(dirPath, path)
		if err != nil {
			return err
		}

		// 跳过根目录本身
		if relPath == "." {
			return nil
		}

		// 检查是否是排除的目录
		if info.IsDir() {
			baseName := filepath.Base(path)
			if excludedDirs[strings.ToLower(baseName)] {
				if s.verbose {
					log.Printf("跳过排除的目录: %s", path)
				}
				return filepath.SkipDir
			}
			return nil
		}

		// 只扫描 C/C++ 文件
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".c", ".cpp", ".cxx", ".cc", ".c++", ".h", ".hpp", ".hxx", ".hh", ".h++":
			mutex.Lock()
			files = append(files, path)
			totalFiles++
			mutex.Unlock()
		}

		return nil
	})

	if err != nil {
		return nil, 0, fmt.Errorf("failed to walk directory %s: %w", dirPath, err)
	}

	// 【修复】重要信息始终显示
	log.Printf("发现 %d 个 C/C++ 文件", totalFiles)

	if len(files) == 0 {
		log.Printf("未找到任何 C/C++ 文件")
		return nil, 0, nil
	}

	// 第一步：执行跨文件分析（符号解析）
	// 【修复】添加进度提示
	log.Printf("开始跨文件分析...")
	crossFileVulns, err := s.performCrossFileAnalysis(ctx, files)
	if err != nil {
		log.Printf("跨文件分析失败: %v", err)
		// 跨文件分析失败不影响后续扫描
	} else {
		log.Printf("跨文件分析完成")
	}

	// 第二步：预扫描收集全局常量数组（V11 语义识别）
	log.Printf("预扫描收集全局常量数组...")
	if err := s.arrayCollector.CollectArrays(ctx, files); err != nil {
		if s.verbose {
			log.Printf("全局数组收集失败: %v", err)
		}
		// 收集失败不影响后续扫描
	} else if s.verbose {
		log.Printf("识别到 %d 个全局常量数组", s.arrayCollector.GetArrayCount())
	}

	// V13 第三步：预扫描收集全局结构体定义
	log.Printf("预扫描收集全局结构体定义...")
	if err := s.structCollector.CollectStructs(ctx, files); err != nil {
		if s.verbose {
			log.Printf("结构体收集失败: %v", err)
		}
		// 收集失败不影响后续扫描
	} else if s.verbose {
		log.Printf("识别到 %d 个结构体定义", s.structCollector.GetStructCount())
	}

	// 第四步：扫描文件列表（根据自动配置选择扫描模式）
	var vulns []Vulnerability
	if s.batchSize > 0 {
		// 使用分批扫描模式（Phase 5 优化）
		if s.verbose {
			log.Printf("使用分批扫描模式: batch-size=%d", s.batchSize)
		}
		vulns, scannedFiles, err = s.scanFilesInBatches(ctx, files, s.batchSize)
	} else {
		// 使用标准扫描模式
		vulns, err = s.scanFilesWithStats(ctx, files, &scannedFiles)
	}
	if err != nil {
		return nil, 0, err
	}

	// 合并跨文件漏洞和本地漏洞
	allVulns := append(vulns, crossFileVulns...)

	// 【修复】重要信息始终显示
	log.Printf("扫描完成: %d/%d 个文件，发现 %d 个漏洞", scannedFiles, totalFiles, len(allVulns))

	return allVulns, scannedFiles, nil
}

// performCrossFileAnalysis 执行跨文件分析
func (s *Scanner) performCrossFileAnalysis(ctx context.Context, files []string) ([]Vulnerability, error) {
	// 创建符号解析器
	resolver := core.NewSymbolResolver(ctx, s.workers)

	// 执行符号解析
	if err := resolver.Process(files); err != nil {
		return nil, fmt.Errorf("符号解析失败: %w", err)
	}

	// 创建跨文件分析器
	crossFileAnalyzer := core.NewCrossFileAnalyzer(ctx, s.workers)

	// 执行跨文件分析
	if err := crossFileAnalyzer.AnalyzeProject(files); err != nil {
		return nil, fmt.Errorf("跨文件分析失败: %w", err)
	}

	// 创建跨文件污点分析器
	// 【Phase 5 优化】传递 CFG 缓存和 worker 数量，避免重复构建
	taintAnalyzer := core.NewCrossFileTaintAnalyzer(ctx, resolver)
	taintAnalyzer.SetCFGCache(s.cfgCache, &s.cfgCacheMu)
	taintAnalyzer.SetWorkers(s.workers)

	// 执行跨文件污点分析
	if err := taintAnalyzer.AnalyzeProject(files); err != nil {
		if s.verbose {
			log.Printf("跨文件污点分析失败: %v", err)
		}
		// 污点分析失败不影响整体扫描
	}

	// 收集所有结果
	var vulns []Vulnerability

	// 1. 跨文件调用漏洞
	results := crossFileAnalyzer.GetResults()
	for _, result := range results {
		vuln := Vulnerability{
			Type:       result.Type,
			Message:    result.Message,
			File:       result.SourceFile,
			Line:       result.SourceLine,
			Column:     0,
			Confidence: result.Confidence,
			Severity:   result.Severity,
			Source:     fmt.Sprintf("Cross-file call to %s in %s", result.Metadata["callee"], result.TargetFile),
		}
		vulns = append(vulns, vuln)
	}

	// 2. 跨文件污点传播漏洞
	taintResults := taintAnalyzer.GetResults()
	for _, result := range taintResults {
		vuln := Vulnerability{
			Type:       "Cross-File Taint Flow",
			Message:    result.Vulnerability,
			File:       result.SourceFile,
			Line:       result.SourceLine,
			Column:     0,
			Confidence: result.Confidence,
			Severity:   result.Severity,
			Source:     fmt.Sprintf("Taint flow: %s -> %s", result.Metadata["source_func"], result.Metadata["sink_func"]),
		}
		vulns = append(vulns, vuln)
	}

	if s.verbose {
		log.Printf("跨文件分析完成: %d 个调用漏洞, %d 个污点漏洞",
			len(results), len(taintResults))
	}

	return vulns, nil
}

// scanFilesWithStats 扫描文件列表并统计
func (s *Scanner) scanFilesWithStats(ctx context.Context, files []string, scannedFiles *int) ([]Vulnerability, error) {
	startTime := time.Now()

	// 创建工作池
	jobs := make(chan string, 100)
	results := make(chan []Vulnerability, 100)
	errors := make(chan error, 100)

	var wg sync.WaitGroup
	var statsMutex sync.Mutex

	// 启动工作协程
	for w := 0; w < s.workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for file := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					// 【超时保护】为每个文件扫描设置120秒超时（可禁用）
					var fileCtx context.Context
					var cancel context.CancelFunc

					if s.disableTimeout {
						fileCtx = ctx
						cancel = func() {} // 空cancel函数
					} else {
						fileCtx, cancel = context.WithTimeout(ctx, 120*time.Second)
					}
					defer cancel()

					// 使用带超时的 channel 来接收结果
					resultChan := make(chan []Vulnerability, 1)
					errChan := make(chan error, 1)

					go func() {
						// 【方案B】传递 workerID 给 ScanFile，从池中获取专用 detector 实例
						vulns, err := s.ScanFile(fileCtx, file, workerID)
						if err != nil {
							errChan <- err
						} else {
							resultChan <- vulns
						}
					}()

					// 等待结果或超时
					select {
					case vulns := <-resultChan:
						results <- vulns
						// 更新统计
						statsMutex.Lock()
						*scannedFiles++
						if s.verbose && *scannedFiles%10 == 0 {
							log.Printf("已扫描 %d/%d 个文件", *scannedFiles, len(files))
						}
						statsMutex.Unlock()
					case err := <-errChan:
						errors <- err
					case <-fileCtx.Done():
						// 超时处理
						log.Printf("警告: 扫描文件超时，跳过: %s", file)
						// 继续处理下一个文件，不阻塞整个批次
					}
				}
			}
		}(w)
	}

	// 发送任务
	go func() {
		for _, file := range files {
			select {
			case <-ctx.Done():
				return
			default:
				jobs <- file
			}
		}
		close(jobs)
	}()

	// 等待完成
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// 收集结果
	var allVulns []Vulnerability
	var scanErrors []error

	for {
		select {
		case vulns, ok := <-results:
			if !ok {
				results = nil
			} else {
				allVulns = append(allVulns, vulns...)
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
			} else {
				scanErrors = append(scanErrors, err)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		if results == nil && errors == nil {
			break
		}
	}

	// 打印扫描错误
	if s.verbose && len(scanErrors) > 0 {
		log.Printf("扫描完成，其中 %d 个错误:", len(scanErrors))
		for _, err := range scanErrors {
			log.Printf("  - %v", err)
		}
	}

	duration := time.Since(startTime)
	// 【修复】重要信息始终显示
	log.Printf("扫描完成: %d 个文件，耗时 %v", len(files), duration)

	return allVulns, nil
}

// scanFilesInBatches 分批扫描文件列表（Phase 5 优化）
// 将文件列表分批处理，每批处理完后触发GC释放内存
func (s *Scanner) scanFilesInBatches(ctx context.Context, files []string, batchSize int) ([]Vulnerability, int, error) {
	if len(files) == 0 {
		return nil, 0, nil
	}

	totalFiles := len(files)
	totalBatches := (totalFiles + batchSize - 1) / batchSize

	// 【修复】重要信息始终显示
	log.Printf("开始分批扫描: %d 个文件，分为 %d 批，每批 %d 个文件",
		totalFiles, totalBatches, batchSize)

	var allVulns []Vulnerability
	totalScanned := 0

	// 分批处理
	for batchNum := 0; batchNum < totalBatches; batchNum++ {
		startIdx := batchNum * batchSize
		endIdx := min(startIdx+batchSize, totalFiles)
		batchFiles := files[startIdx:endIdx]

		// 【修复】重要进度信息始终显示
		log.Printf("[批次 %d/%d] 扫描 %d 个文件 (%d-%d)",
			batchNum+1, totalBatches, len(batchFiles), startIdx, endIdx-1)

		// 扫描当前批次
		scannedInBatch := 0
		batchVulns, err := s.scanFilesWithStats(ctx, batchFiles, &scannedInBatch)
		if err != nil {
			log.Printf("警告: 批次 %d 扫描失败: %v", batchNum+1, err)
		}

		// 累积结果
		allVulns = append(allVulns, batchVulns...)
		totalScanned += scannedInBatch

		// 【修复】重要进度信息始终显示
		log.Printf("[批次 %d/%d] 完成: 发现 %d 个漏洞，总计 %d 个漏洞",
			batchNum+1, totalBatches, len(batchVulns), len(allVulns))


		// Phase 5: 每批处理后主动触发 GC 以释放内存
		if batchNum < totalBatches-1 { // 最后一批不需要 GC
			runtime.GC()
			runtime.GC() // 两次 GC 确保清理彻底
		}
	}

	return allVulns, totalScanned, nil
}

// ScanFiles 扫描文件列表 (保留原有接口)
func (s *Scanner) scanFiles(ctx context.Context, files []string) ([]Vulnerability, error) {
	// V13: 单文件扫描也需要预扫描收集结构体定义
	if s.verbose {
		log.Printf("预扫描收集全局结构体定义...")
	}
	if err := s.structCollector.CollectStructs(ctx, files); err != nil {
		if s.verbose {
			log.Printf("结构体收集失败: %v", err)
		}
	} else if s.verbose {
		log.Printf("识别到 %d 个结构体定义", s.structCollector.GetStructCount())
	}

	// V13: 单文件扫描也需要预扫描收集全局数组
	if s.verbose {
		log.Printf("预扫描收集全局常量数组...")
	}
	if err := s.arrayCollector.CollectArrays(ctx, files); err != nil {
		if s.verbose {
			log.Printf("全局数组收集失败: %v", err)
		}
	} else if s.verbose {
		log.Printf("识别到 %d 个全局常量数组", s.arrayCollector.GetArrayCount())
	}

	var scanned int
	return s.scanFilesWithStats(ctx, files, &scanned)
}

// printResults 打印结果
func (s *Scanner) printResults(vulns []Vulnerability, duration time.Duration, filesScanned int) {
	// 准备扫描结果
	result := &report.ScanResult{
		Vulnerabilities: convertToReportVulns(vulns),
		Duration:        duration,
		FilesScanned:    filesScanned,
		DetectorsUsed:   s.getDetectorNames(),
	}

	// 如果指定了输出文件，保存到文件
	if s.outputFile != "" {
		// 确定输出文件路径
		outputPath := s.outputFile

		// 如果启用了时间戳，在文件名中插入时间戳
		if s.timestamp {
			ext := filepath.Ext(s.outputFile)
			base := strings.TrimSuffix(s.outputFile, ext)
			timestamp := time.Now().Format("20060102_150405")
			outputPath = fmt.Sprintf("%s_%s%s", base, timestamp, ext)
		}

		// 创建输出目录（如果不存在）
		outputDir := filepath.Dir(outputPath)
		if outputDir != "." && outputDir != "" {
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				log.Printf("Failed to create output directory: %v", err)
				return
			}
		}

		// 对于 'all' 格式，使用报告管理器生成所有格式
		if s.outputFormat == report.FormatAll {
			opts := []report.ManagerOption{
				report.WithFormat(s.outputFormat),
				report.WithOutputDir(outputDir),
			}
			if s.timestamp {
				opts = append(opts, report.WithTimestamp())
			}
			mgr := report.NewManager(opts...)
			outputFiles, err := mgr.Generate(result)
			if err != nil {
				log.Printf("Failed to generate report: %v", err)
				return
			}
			fmt.Printf("\nReport generated:\n")
			for _, file := range outputFiles {
				fmt.Printf("  %s\n", file)
			}
			return
		}

		// 创建输出文件
		file, err := os.Create(outputPath)
		if err != nil {
			log.Printf("Failed to create output file %s: %v", outputPath, err)
			return
		}
		defer file.Close()

		// 根据格式创建对应的 writer
		var writer interface{ Write(*report.ScanResult) error }
		switch s.outputFormat {
		case report.FormatJSON:
			writer = report.NewJSONWriter(file)
		case report.FormatSARIF:
			writer = report.NewSARIFWriter(file)
		case report.FormatText:
			writer = report.NewTextWriter(file)
		default:
			log.Printf("Unsupported output format: %v", s.outputFormat)
			return
		}

		// 写入报告
		if err := writer.Write(result); err != nil {
			log.Printf("Failed to write report to %s: %v", outputPath, err)
			return
		}

		fmt.Printf("\nReport generated: %s\n", outputPath)
	}

	// 总是输出到控制台（text 格式），除非是 JSON/SARIF 格式且指定了输出文件
	if s.outputFormat == report.FormatText || s.outputFile == "" {
		// 【控制台摘要】只显示统计信息，不显示漏洞详情
		fmt.Printf("\nScan Summary\n")
		fmt.Printf("===========\n")
		fmt.Printf("Files scanned: %d\n", result.FilesScanned)
		fmt.Printf("Scan time: %s\n", result.Duration.Round(time.Millisecond))

		// 统计各严重级别的漏洞数量
		counts := make(map[string]int)
		for _, vuln := range result.Vulnerabilities {
			counts[vuln.Severity]++
		}

		// 显示统计
		if len(counts) > 0 {
			fmt.Printf("\nVulnerabilities found:\n")
			if counts["critical"] > 0 {
				fmt.Printf("  CRITICAL: %d\n", counts["critical"])
			}
			if counts["high"] > 0 {
				fmt.Printf("  HIGH: %d\n", counts["high"])
			}
			if counts["medium"] > 0 {
				fmt.Printf("  MEDIUM: %d\n", counts["medium"])
			}
			if counts["low"] > 0 {
				fmt.Printf("  LOW: %d\n", counts["low"])
			}
			fmt.Printf("  TOTAL: %d\n", len(result.Vulnerabilities))
		} else {
			fmt.Printf("\n✓ No vulnerabilities found\n")
		}

		if s.outputFile != "" {
			fmt.Printf("\nDetailed report saved to: %s\n", s.outputFile)
		}
		fmt.Printf("\n")
	}
}

// convertToReportVulns 转换为报告漏洞结构
func convertToReportVulns(vulns []Vulnerability) []report.Vulnerability {
	result := make([]report.Vulnerability, len(vulns))
	for i, vuln := range vulns {
		result[i] = report.Vulnerability{
			Type:       vuln.Type,
			Message:    vuln.Message,
			File:       vuln.File,
			Line:       vuln.Line,
			Column:     vuln.Column,
			Severity:   vuln.Severity,
			Confidence: vuln.Confidence,
			Source:     vuln.Source,
		}
	}
	return result
}

// getDetectorNames 获取检测器名称列表
func (s *Scanner) getDetectorNames() []string {
	names := make([]string, len(s.detectors))
	for i, detector := range s.detectors {
		names[i] = detector.Name()
	}
	return names
}

func main() {
	// Phase 4 优化：智能默认配置
	// 根据 CPU 核心数自动调整 workers，但不低于 4，不超过 32
	defaultWorkers := runtime.NumCPU()
	if defaultWorkers < 4 {
		defaultWorkers = 4
	}
	if defaultWorkers > 32 {
		defaultWorkers = 32
	}

	var (
		workers     = flag.Int("workers", defaultWorkers, "Number of worker goroutines (default: NumCPU, capped at 32)")
		verbose     = flag.Bool("v", false, "Verbose output")
		format      = flag.String("format", "text", "Output format (text, json, sarif, all)")
		output      = flag.String("output", "", "Output file path for report (e.g., report.json)")
		timestamp   = flag.Bool("timestamp", false, "Add timestamp to output files")
		listFormats = flag.Bool("list-formats", false, "List supported output formats")
		help        = flag.Bool("help", false, "Show help")
		// Phase 4 新增配置选项
		cacheSize   = flag.Int("cache-size", 10000, "File cache size (number of files)")
		maxMemoryGB = flag.Int("max-memory", 64, "Maximum memory limit in GB (0 = no limit)")
		monitorMem  = flag.Bool("monitor-memory", true, "Enable memory usage monitoring")
		// Phase 5 新增配置选项
		batchSize = flag.Int("batch-size", 0, "Batch size for file scanning (0 = no batching, default: 100 for large projects)")
		// 【调试】禁用超时保护
		disableTimeout = flag.Bool("disable-timeout", false, "Disable timeout protection for debugging")
		// 检测器过滤选项
		detector = flag.String("detector", "", "Run only specified detector (uninit, uaf, buffer, heap, null, oob, int, underflow, leak, typeconf, atomicity, deadlock, signed, race, format, injection, path, all)")
	)
	flag.Parse()

	// Phase 4: 验证配置参数
	if *maxMemoryGB < 0 {
		log.Fatalf("Invalid max-memory value: %d (must be >= 0)", *maxMemoryGB)
	}
	if *cacheSize < 0 {
		log.Fatalf("Invalid cache-size value: %d (must be >= 0)", *cacheSize)
	}

	// Phase 5: 验证分批配置参数
	if *batchSize < 0 {
		log.Fatalf("Invalid batch-size value: %d (must be >= 0)", *batchSize)
	}

	// Phase 4: 显示配置信息（仅 verbose 模式）
	if *verbose {
		mode := "standard"
		if *batchSize > 0 {
			mode = fmt.Sprintf("batch (size=%d)", *batchSize)
		}
		log.Printf("Configuration: workers=%d, cache-size=%d, max-memory=%dGB, mode=%s",
			*workers, *cacheSize, *maxMemoryGB, mode)
	}

	// Phase 4: 内存监控辅助函数
	logMemoryUsage := func(phase string) {
		if !*monitorMem {
			return
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Printf("[%s] Memory: Alloc=%.2f MB, Sys=%.2f MB, HeapAlloc=%.2f MB, HeapSys=%.2f MB",
			phase,
			float64(m.Alloc)/1024/1024,
			float64(m.Sys)/1024/1024,
			float64(m.HeapAlloc)/1024/1024,
			float64(m.HeapSys)/1024/1024,
		)
	}

	// Phase 5: 自动项目规模检测和参数配置
	autoConfigure := func(dirPath string) (int, string) {
		// 如果用户手动指定了参数，则不进行自动配置
		if *batchSize > 0 {
			log.Printf("使用用户指定的配置: batch-size=%d", *batchSize)
			return *batchSize, "user-specified"
		}

		// 快速统计 C/C++ 文件数量
		var fileCount int
		// 【修复】使用统一的排除目录列表
		excludedDirs := getExcludedDirs()

		_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // 跳过错误，继续统计
			}

			relPath, err := filepath.Rel(dirPath, path)
			if err != nil {
				return nil
			}
			if relPath == "." {
				return nil
			}

			if info.IsDir() {
				baseName := filepath.Base(path)
				if excludedDirs[strings.ToLower(baseName)] {
					return filepath.SkipDir
				}
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			switch ext {
			case ".c", ".cpp", ".cxx", ".cc", ".c++", ".h", ".hpp", ".hxx", ".hh", ".h++":
				fileCount++
			}
			return nil
		})

		// 根据文件数量自动配置
		var recommendedBatchSize int
		var scale string

		switch {
		case fileCount < 100:
			// 小型项目: < 100 文件
			recommendedBatchSize = 0 // 不分批
			scale = "small"
		case fileCount < 1000:
			// 中型项目: 100-1000 文件
			recommendedBatchSize = 100
			scale = "medium"
		case fileCount < 10000:
			// 大型项目: 1000-10000 文件
			recommendedBatchSize = 100
			scale = "large"
		default:
			// 超大型项目: > 10000 文件
			recommendedBatchSize = 100
			scale = "xlarge"
		}

		// 【修复】项目规模自动检测信息始终显示（不依赖 verbose）
		// 这是用户需要的重要配置信息
		log.Printf("项目规模自动检测: %d 个 C/C++ 文件 -> %s 项目",
			fileCount, scale)
		if recommendedBatchSize > 0 {
			log.Printf("自动配置: batch-size=%d", recommendedBatchSize)
		}

		return recommendedBatchSize, scale
	}

	// 列出支持的格式
	if *listFormats {
		fmt.Printf("Supported output formats:\n")
		for _, f := range report.SupportedFormats() {
			fmt.Printf("  %s - %s\n", f, report.FormatDescription(f))
		}
		os.Exit(0)
	}

	if *help {
		fmt.Printf("GoSAST - Static Application Security Testing for C/C++\n\n")
		fmt.Printf("Usage: %s [options] <path>\n\n", os.Args[0])
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
		fmt.Printf("\nSupported formats: text, json, sarif, all\n")
		fmt.Printf("\nExamples:\n")
		fmt.Printf("  %s /path/to/project\n", os.Args[0])
		fmt.Printf("  %s -workers 8 -v /path/to/project\n", os.Args[0])
		fmt.Printf("  %s -format json -output report.json /path/to/project\n", os.Args[0])
		fmt.Printf("  %s -format json -output reports/scan.json /path/to/project\n", os.Args[0])
		fmt.Printf("  %s -format json -output report.json -timestamp /path/to/project\n", os.Args[0])
		fmt.Printf("  %s -format all -output reports/scan /path/to/project\n", os.Args[0])
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Error: Please provide a file or directory to scan\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// 解析输出格式
	outputFormat, err := report.ParseFormat(*format)
	if err != nil {
		log.Fatalf("Invalid output format: %v", err)
	}

	path := flag.Arg(0)

	// 创建扫描器
	scanner := NewScanner(*workers, *verbose, outputFormat, *output, *timestamp)
	scanner.disableTimeout = *disableTimeout

	// 添加检测器 - 根据 --detector 参数选择性激活
	detectorFlag := *detector
	log.Printf("[DEBUG] detector flag value: '%s'", detectorFlag)
	shouldAddDetector := func(detName string) bool {
		if detectorFlag == "" || detectorFlag == "all" {
			log.Printf("[DEBUG] All detectors enabled (detName=%s)", detName)
			return true // 默认启用所有
		}
		matched := detectorFlag == detName
		log.Printf("[DEBUG] Checking %s: matched=%v (requested='%s')", detName, matched, detectorFlag)
		return matched
	}

	if shouldAddDetector("uaf") {
		scanner.AddDetector(detectors.NewUAFDetectorImproved())       // 改进的 UAF 检测器
	}
	if shouldAddDetector("doublefree") {
		scanner.AddDetector(detectors.NewDoubleFreeDetectorImproved()) // 改进的 Double Free 检测器
	}
	if shouldAddDetector("int") {
		scanner.AddDetector(detectors.NewIntOverflowDetectorImproved()) // 改进的整数溢出检测器
	}
	if shouldAddDetector("buffer") {
		scanner.AddDetector(detectors.NewBufferOverflowDetector())
	}
	if shouldAddDetector("heap") {
		scanner.AddDetector(detectors.NewHeapOverflowDetector())        // 堆溢出检测器（跨过程分析）
	}
	if shouldAddDetector("null") {
		scanner.AddDetector(detectors.NewNullPointerDereferenceDetector()) // 空指针解引用检测器（基于 API 契约）
	}
	if shouldAddDetector("format") {
		scanner.AddDetector(detectors.NewFormatStringDetector())      // V2: 已修复栈溢出问题
	}
	if shouldAddDetector("injection") {
		scanner.AddDetector(detectors.NewCommandInjectionDetector())
	}
	if shouldAddDetector("oob") {
		scanner.AddDetector(detectors.NewOOBReadDetector())           // OOB Read 检测器（越界读取）
	}
	if shouldAddDetector("deadlock") {
		scanner.AddDetector(detectors.NewDeadlockDetector())          // Deadlock 检测器（死锁检测）
	}
	if shouldAddDetector("signed") {
		scanner.AddDetector(detectors.NewSignedToUnsignedDetector())  // CWE-195 检测器
	}
	if shouldAddDetector("race") {
		scanner.AddDetector(detectors.NewDataRaceDetector())         // Data Race 检测器（数据竞争）
	}
	if shouldAddDetector("underflow") {
		// 【禁用】Integer Underflow检测器 - 已禁用以达到<200误报目标
		// scanner.AddDetector(detectors.NewIntegerUnderflowDetector()) // Integer Underflow 检测器 (CWE-191)
	}
	if shouldAddDetector("leak") {
		scanner.AddDetector(detectors.NewMemoryLeakDetector()) // Memory Leak 检测器 (CWE-401)
	}
	if shouldAddDetector("typeconf") {
		scanner.AddDetector(detectors.NewTypeConfusionDetector()) // Type Confusion 检测器 (CWE-843)
	}
	if shouldAddDetector("atomicity") {
		scanner.AddDetector(detectors.NewAtomicityViolationDetector()) // Atomicity Violation 检测器 (CWE-360)
	}
	if shouldAddDetector("path") {
		scanner.AddDetector(detectors.NewPathTraversalDetector()) // Path Traversal 检测器 (CWE-22)
	}
	// 未初始化变量检测器已暂时禁用
	// if shouldAddDetector("uninit") {
	// 	scanner.AddDetector(detectors.NewUninitVarSSADetector()) // 基于 SSA 的未初始化变量检测器 (2024-2025)
	// }

	if len(scanner.detectors) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: No detectors configured\n")
	}

	// 【方案B】完成检测器初始化，为每个 worker 创建独立的 detector 实例
	if err := scanner.FinalizeDetectors(); err != nil {
		log.Fatalf("Failed to finalize detectors: %v", err)
	}
	log.Printf("Detector pool initialized: %d workers, %d detectors\n", *workers, len(scanner.detectors))

	// 创建上下文
	ctx := context.Background()

	// 检查路径
	info, err := os.Stat(path)
	if err != nil {
		log.Fatalf("Error accessing path %s: %v", path, err)
	}

	// Phase 5: 自动项目规模检测和参数配置
	if info.IsDir() {
		// 只对目录扫描进行自动配置
		autoBatchSize, scale := autoConfigure(path)
		scanner.SetAutoConfig(autoBatchSize, scale)
	}

	// 记录开始时间
	startTime := time.Now()

	// Phase 4: 记录初始内存使用
	logMemoryUsage("Start")

	// 开始扫描
	var vulns []Vulnerability
	var filesScanned int
	if info.IsDir() {
		vulns, filesScanned, err = scanner.ScanDir(ctx, path)
		if err != nil {
			log.Fatalf("目录扫描失败: %v", err)
		}
		// 【移除重复日志】ScanDir 内部已经输出 "扫描完成: X 个文件，发现 Y 个漏洞"
	} else {
		vulns, err = scanner.scanFiles(ctx, []string{path})
		filesScanned = 1
		if err != nil {
			log.Fatalf("扫描失败: %v", err)
		}
	}

	// Phase 4: 记录扫描后内存使用
	logMemoryUsage("Complete")

	// 计算扫描时间
	duration := time.Since(startTime)

	// 打印结果
	scanner.printResults(vulns, duration, filesScanned)

	// 打印检测器耗时统计
	scanner.printDetectorTimings()
}