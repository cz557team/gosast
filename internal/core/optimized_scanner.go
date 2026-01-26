package core

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OptimizedScanner 优化的扫描器
type OptimizedScanner struct {
	fileCache     *OptimizedFileCache
	workers       int
	verbose       bool
	monitor       *PerformanceMonitor
	workerPool    *WorkerPool
	earlyExit     bool
	skipProcessed bool
	maxMemory     int64
}

// NewOptimizedScanner 创建优化的扫描器
func NewOptimizedScanner(ctx context.Context, workers int, verbose bool, cacheSize int, maxMemory int64) *OptimizedScanner {
	cache := NewOptimizedFileCache(ctx, cacheSize, maxMemory)
	monitor := NewPerformanceMonitor(verbose, func(msg string) {
		if verbose {
			log.Print(msg)
		}
	})
	workerPool := NewWorkerPool(ctx, workers, 1000) // 队列大小1000

	return &OptimizedScanner{
		fileCache:     cache,
		workers:       workers,
		verbose:       verbose,
		monitor:       monitor,
		workerPool:    workerPool,
		maxMemory:     maxMemory,
		skipProcessed: true, // 默认跳过已处理文件
	}
}

// ScanJob 扫描任务
type ScanJob struct {
	FilePath      string
	jobID         string
	scanner       *OptimizedScanner
	detectors     []interface{} // 使用interface{}避免循环导入
	resultCh      chan ScanResult
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

// ScanResult 扫描结果
type ScanResult struct {
	FilePath     string
	Vulnerabilities []Vulnerability
	Error        error
	Duration     time.Duration
}

// ID 返回任务ID
func (sj *ScanJob) ID() string {
	return sj.jobID
}

// Run 运行扫描任务
func (sj *ScanJob) Run() error {
	startTime := time.Now()

	// 使用计时器
	timer := sj.scanner.monitor.NewTimer("scan_job", map[string]string{
		"file": filepath.Base(sj.FilePath),
	})
	defer timer.Stop()

	// 获取文件缓存
	unit, err := sj.scanner.fileCache.Get(sj.FilePath)
	if err != nil {
		sj.resultCh <- ScanResult{
			FilePath:     sj.FilePath,
			Vulnerabilities: nil,
			Error:        err,
			Duration:     time.Since(startTime),
		}
		return err
	}

	// 构建CFG
	cfg, err := BuildCFG(&ParsedUnit{
		FilePath: unit.FilePath,
		Root:     unit.Tree.RootNode(),
		Source:   unit.Source,
		Tree:     unit.Tree,
			Language: "c",
	})
	if err != nil {
		cfg = NewCFG()
	}

	// 并行运行检测器
	var vulns []Vulnerability
	var mu sync.Mutex
	var detectorWG sync.WaitGroup

	for _, detector := range sj.detectors {
		detectorWG.Add(1)
		go func(d interface{}) {
			defer detectorWG.Done()

			// 类型断言获取Detector接口
			detectorInterface, ok := d.(interface {
				Name() string
				Run(ctx *AnalysisContext) ([]Vulnerability, error)
			})
			if !ok {
				return
			}

			// 为每个检测器创建独立的分析上下文
			detectorCtx := NewAnalysisContext(&ParsedUnit{
				FilePath: unit.FilePath,
				Root:     unit.Tree.RootNode(),
				Source:   unit.Source,
				Tree:     unit.Tree.Copy(),
				Language: "c",
			})
			detectorCtx.CFG = cfg

			detectorVulns, err := detectorInterface.Run(detectorCtx)
			if err != nil {
				return
			}

			mu.Lock()
			vulns = append(vulns, detectorVulns...)
			mu.Unlock()
		}(detector)
	}

	detectorWG.Wait()

	sj.resultCh <- ScanResult{
		FilePath:     sj.FilePath,
		Vulnerabilities: vulns,
		Error:        nil,
		Duration:     time.Since(startTime),
	}

	return nil
}

// ScanDir 扫描目录
func (os *OptimizedScanner) ScanDir(ctx context.Context, dirPath string, detectors []interface{}) ([]Vulnerability, int, error) {
	timer := os.monitor.NewTimer("scan_dir", map[string]string{
		"dir": dirPath,
	})
	defer timer.Stop()

	// 收集文件
	files, err := os.collectFiles(dirPath)
	if err != nil {
		return nil, 0, err
	}

	// 预加载文件到缓存
	preloadStart := time.Now()
	os.fileCache.Preload(files)
	os.monitor.RecordTimer("preload_time", time.Since(preloadStart), nil)

	// 启动工作池
	os.workerPool.Start()

	// 创建结果通道（带缓冲以减少阻塞）
	resultCh := make(chan ScanResult, len(files))

	// 提交扫描任务
	for i, file := range files {
		job := &ScanJob{
			FilePath:      file,
			jobID:         fmt.Sprintf("scan_%d", i),
			scanner:       os,
			detectors:     detectors,
			resultCh:      resultCh,
		}

		if err := os.workerPool.Submit(job); err != nil {
			continue
		}
	}

	// 并行结果收集（Fan-Out 模式）
	const resultWorkers = 4 // 并行结果收集器数量
	var scannedFiles int64
	var wg sync.WaitGroup

	// 使用分片减少锁竞争：每个收集器维护自己的 slice
	vulnsSlices := make([][]Vulnerability, resultWorkers)

	// 启动多个并行结果收集器
	for workerID := 0; workerID < resultWorkers; workerID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			localVulns := make([]Vulnerability, 0, 100) // 预分配减少扩容

			for result := range resultCh {
				if result.Error == nil {
					atomic.AddInt64(&scannedFiles, 1)
					// 直接 append 到本地 slice，无锁
					localVulns = append(localVulns, result.Vulnerabilities...)
				}

				// 记录文件扫描时间（无锁）
				os.monitor.RecordTimer("file_scan_time", result.Duration, map[string]string{
					"file": filepath.Base(result.FilePath),
				})
			}

			// 存储到分片
			vulnsSlices[id] = localVulns
		}(workerID)
	}

	// 等待所有任务提交完成
	os.workerPool.Stop()

	// 关闭结果通道，触发收集器退出
	close(resultCh)

	// 等待所有收集器完成
	wg.Wait()

	// 合并所有分片的结果（最后一次性合并）
	var totalVulns []Vulnerability
	for _, slice := range vulnsSlices {
		totalVulns = append(totalVulns, slice...)
	}

	// 打印性能摘要
	os.monitor.PrintSummary()

	return totalVulns, int(scannedFiles), nil
}

// collectFiles 收集文件
func (os *OptimizedScanner) collectFiles(dirPath string) ([]string, error) {
	timer := os.monitor.NewTimer("collect_files", nil)
	defer timer.Stop()

	var files []string
	excludedDirs := map[string]bool{
		"build":         true,
		"dist":          true,
		"vendor":        true,
		"node_modules":  true,
		".git":          true,
		".svn":          true,
		".hg":           true,
		"third_party":   true,
		"thirdparty":    true,
		"3rdparty":      true,
		"deps":          true,
		"dependency":    true,
		"libraries":     true,
		"lib":           true,
		"external":      true,
		"externals":     true,
		".cache":        true,
		".idea":         true,
		".vscode":       true,
		"__pycache__":   true,
		".pytest_cache": true,
		"target":        true,
		"cmake-build":   true,
		".cmake":        true,
	}

	err := filepath.Walk(dirPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 获取相对路径
		relPath, err := filepath.Rel(dirPath, path)
		if err != nil {
			return err
		}

		// 跳过根目录
		if relPath == "." {
			return nil
		}

		// 检查是否是排除的目录
		if info.IsDir() {
			baseName := filepath.Base(path)
			if excludedDirs[strings.ToLower(baseName)] {
				return filepath.SkipDir
			}
			return nil
		}

		// 只扫描C/C++文件
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".c", ".cpp", ".cxx", ".cc", ".c++", ".h", ".hpp", ".hxx", ".hh", ".h++":
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

// GetStats 获取性能统计
func (os *OptimizedScanner) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"cache_stats":   os.fileCache.GetStats(),
		"worker_stats":  os.workerPool.GetStats(),
		"metrics":       os.monitor.GetAllMetrics(),
	}

	return stats
}

// SetEarlyExit 设置早停
func (os *OptimizedScanner) SetEarlyExit(enabled bool) {
	os.earlyExit = enabled
}

// SetSkipProcessed 设置跳过已处理文件
func (os *OptimizedScanner) SetSkipProcessed(enabled bool) {
	os.skipProcessed = enabled
}

// === Phase 5: 分批扫描优化 ===

// ScanDirInBatches 分批扫描目录（Phase 5 优化）
// 将文件列表分批处理，每批处理完后释放内存
// batchSize: 每批处理的文件数（默认 100）
// onBatchComplete: 每批完成后的回调（可用于内存统计）
func (os *OptimizedScanner) ScanDirInBatches(
	ctx context.Context,
	dirPath string,
	detectors []interface{},
	batchSize int,
	onBatchComplete func(batchNum int, filesScanned int, vulns []Vulnerability),
) ([]Vulnerability, int, error) {
	if batchSize <= 0 {
		batchSize = 100 // 默认每批 100 个文件
	}

	// 收集所有文件
	allFiles, err := os.collectFiles(dirPath)
	if err != nil {
		return nil, 0, err
	}

	totalFiles := len(allFiles)
	if totalFiles == 0 {
		return nil, 0, nil
	}

	// 计算批次数
	totalBatches := (totalFiles + batchSize - 1) / batchSize

	var allVulns []Vulnerability
	totalScanned := 0

	// 分批处理
	for batchNum := 0; batchNum < totalBatches; batchNum++ {
		startIdx := batchNum * batchSize
		endIdx := min(startIdx+batchSize, totalFiles)
		batchFiles := allFiles[startIdx:endIdx]

		if os.verbose {
			log.Printf("[Batch %d/%d] Processing %d files (%d-%d)",
				batchNum+1, totalBatches, len(batchFiles), startIdx, endIdx-1)
		}

		// 扫描当前批次
		batchVulns, scanned, err := os.scanBatch(ctx, batchFiles, detectors)
		if err != nil {
			log.Printf("Warning: batch %d failed: %v", batchNum+1, err)
		}

		// 累积结果
		allVulns = append(allVulns, batchVulns...)
		totalScanned += scanned

		// 调用回调
		if onBatchComplete != nil {
			onBatchComplete(batchNum+1, scanned, batchVulns)
		}

		// Phase 5: 每批处理后主动触发 GC 以释放内存
		if batchNum < totalBatches-1 { // 最后一批不需要 GC
			runtime.GC()
			runtime.GC() // 两次 GC 确保清理彻底
		}

		if os.verbose {
			log.Printf("[Batch %d/%d] Completed: %d vulns found, total: %d vulns",
				batchNum+1, totalBatches, len(batchVulns), len(allVulns))
		}
	}

	return allVulns, totalScanned, nil
}

// scanBatch 扫描一批文件（Phase 5 辅助方法）
func (os *OptimizedScanner) scanBatch(
	ctx context.Context,
	files []string,
	detectors []interface{},
) ([]Vulnerability, int, error) {
	if len(files) == 0 {
		return nil, 0, nil
	}

	// 启动工作池
	os.workerPool.Start()
	defer os.workerPool.Stop()

	// 创建结果通道
	resultCh := make(chan ScanResult, len(files))

	// 提交扫描任务
	for i, file := range files {
		job := &ScanJob{
			FilePath:  file,
			jobID:     fmt.Sprintf("batch_scan_%d", i),
			scanner:   os,
			detectors: detectors,
			resultCh:  resultCh,
		}

		if err := os.workerPool.Submit(job); err != nil {
			log.Printf("Warning: failed to submit job for %s: %v", file, err)
		}
	}

	// 并行结果收集
	const resultWorkers = 4
	var scannedFiles int64
	var wg sync.WaitGroup
	vulnsSlices := make([][]Vulnerability, resultWorkers)

	for workerID := 0; workerID < resultWorkers; workerID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			localVulns := make([]Vulnerability, 0, 50)

			for result := range resultCh {
				if result.Error == nil {
					atomic.AddInt64(&scannedFiles, 1)
					localVulns = append(localVulns, result.Vulnerabilities...)
				}
			}

			vulnsSlices[id] = localVulns
		}(workerID)
	}

	// 等待所有任务完成
	os.workerPool.Stop()
	close(resultCh)
	wg.Wait()

	// 合并结果
	var totalVulns []Vulnerability
	for _, slice := range vulnsSlices {
		totalVulns = append(totalVulns, slice...)
	}

	return totalVulns, int(scannedFiles), nil
}
