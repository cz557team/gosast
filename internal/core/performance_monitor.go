package core

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Metrics 性能指标
type Metrics struct {
	Name      string        `json:"name"`
	Value     float64       `json:"value"`
	Unit      string        `json:"unit"`
	Timestamp time.Time     `json:"timestamp"`
	Tags      map[string]string `json:"tags"`
}

// PerformanceMonitor 性能监控器
type PerformanceMonitor struct {
	metrics     map[string][]Metrics
	mutex       sync.RWMutex
	startTime   time.Time
	enabled     bool
	logger      func(string)
}

// NewPerformanceMonitor 创建性能监控器
func NewPerformanceMonitor(enabled bool, logger func(string)) *PerformanceMonitor {
	pm := &PerformanceMonitor{
		metrics:   make(map[string][]Metrics),
		startTime: time.Now(),
		enabled:   enabled,
		logger:    logger,
	}

	if enabled {
		pm.StartGoroutineStatsCollection()
	}

	return pm
}

// Record 记录指标
func (pm *PerformanceMonitor) Record(name string, value float64, unit string, tags map[string]string) {
	if !pm.enabled {
		return
	}

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	metrics := pm.metrics[name]
	metrics = append(metrics, Metrics{
		Name:      name,
		Value:     value,
		Unit:      unit,
		Timestamp: time.Now(),
		Tags:      tags,
	})

	// 保持最近1000个数据点
	if len(metrics) > 1000 {
		metrics = metrics[1:]
	}
	pm.metrics[name] = metrics
}

// RecordTimer 记录时间指标
func (pm *PerformanceMonitor) RecordTimer(name string, duration time.Duration, tags map[string]string) {
	pm.Record(name, duration.Seconds(), "s", tags)
}

// RecordGauge 记录仪表指标
func (pm *PerformanceMonitor) RecordGauge(name string, value float64, unit string, tags map[string]string) {
	pm.Record(name, value, unit, tags)
}

// RecordCounter 记录计数器
func (pm *PerformanceMonitor) RecordCounter(name string, value float64, tags map[string]string) {
	pm.Record(name, value, "count", tags)
}

// GetMetrics 获取指标
func (pm *PerformanceMonitor) GetMetrics(name string) []Metrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	metrics := pm.metrics[name]
	result := make([]Metrics, len(metrics))
	copy(result, metrics)
	return result
}

// GetAllMetrics 获取所有指标
func (pm *PerformanceMonitor) GetAllMetrics() map[string][]Metrics {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	result := make(map[string][]Metrics)
	for name, metrics := range pm.metrics {
		result[name] = append([]Metrics(nil), metrics...)
	}
	return result
}

// StartGoroutineStatsCollection 启动协程统计收集
func (pm *PerformanceMonitor) StartGoroutineStatsCollection() {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				pm.collectGoroutineStats()
			}
		}
	}()
}

// collectGoroutineStats 收集协程统计
func (pm *PerformanceMonitor) collectGoroutineStats() {
	runtime.GC() // 强制GC以获取准确的内存统计

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	pm.RecordGauge("goroutines", float64(runtime.NumGoroutine()), "count", nil)
	pm.RecordGauge("memory_alloc", float64(memStats.Alloc), "bytes", nil)
	pm.RecordGauge("memory_sys", float64(memStats.Sys), "bytes", nil)
	pm.RecordGauge("memory_heap_alloc", float64(memStats.HeapAlloc), "bytes", nil)
	pm.RecordGauge("memory_heap_sys", float64(memStats.HeapSys), "bytes", nil)
	pm.RecordGauge("gc_pause_total", float64(memStats.PauseTotalNs), "ns", nil)
	pm.RecordGauge("gc_count", float64(memStats.NumGC), "count", nil)

	// 计算GC频率
	pm.RecordGauge("gc_frequency", pm.calculateGCFrequency(), "Hz", nil)
}

// calculateGCFrequency 计算GC频率
func (pm *PerformanceMonitor) calculateGCFrequency() float64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	elapsed := time.Since(pm.startTime).Seconds()
	if elapsed <= 0 || memStats.NumGC <= 0 {
		return 0
	}

	return float64(memStats.NumGC) / elapsed
}

// PrintSummary 打印性能摘要
func (pm *PerformanceMonitor) PrintSummary() {
	if !pm.enabled || pm.logger == nil {
		return
	}

	pm.logger("=== 性能监控摘要 ===")

	// 打印主要指标
	metrics := pm.GetAllMetrics()

	if goroutines, ok := metrics["goroutines"]; ok && len(goroutines) > 0 {
		pm.logger(fmt.Sprintf("协程数量: %.2f", getLatestValue(goroutines)))
	}

	if memory, ok := metrics["memory_alloc"]; ok && len(memory) > 0 {
		value := getLatestValue(memory)
		pm.logger(fmt.Sprintf("内存使用: %.2f MB", value/1024/1024))
	}

	if gcFreq, ok := metrics["gc_frequency"]; ok && len(gcFreq) > 0 {
		pm.logger(fmt.Sprintf("GC频率: %.2f Hz", getLatestValue(gcFreq)))
	}

	pm.logger("=== 监控结束 ===")
}

// getLatestValue 获取最新值
func getLatestValue(metrics []Metrics) float64 {
	if len(metrics) == 0 {
		return 0
	}
	return metrics[len(metrics)-1].Value
}

// Timer 计时器
type Timer struct {
	start    time.Time
	name    string
	monitor *PerformanceMonitor
	tags    map[string]string
}

// NewTimer 创建计时器
func (pm *PerformanceMonitor) NewTimer(name string, tags map[string]string) *Timer {
	return &Timer{
		start:    time.Now(),
		name:    name,
		monitor: pm,
		tags:    tags,
	}
}

// Stop 停止计时器
func (t *Timer) Stop() {
	duration := time.Since(t.start)
	t.monitor.RecordTimer(t.name, duration, t.tags)
}

// WithTimer 计时包装器
func (pm *PerformanceMonitor) WithTimer(name string, tags map[string]string, fn func()) {
	timer := pm.NewTimer(name, tags)
	defer timer.Stop()
	fn()
}

// BenchmarkResult 基准测试结果
type BenchmarkResult struct {
	Name         string        `json:"name"`
	Iterations   int           `json:"iterations"`
	TotalTime    time.Duration `json:"total_time"`
	AvgTime      time.Duration `json:"avg_time"`
	MinTime      time.Duration `json:"min_time"`
	MaxTime      time.Duration `json:"max_time"`
	StdDeviation time.Duration `json:"std_deviation"`
	Throughput   float64       `json:"throughput"` // ops/sec
}

// Benchmark 性能基准测试
func (pm *PerformanceMonitor) Benchmark(name string, iterations int, fn func()) BenchmarkResult {
	start := time.Now()
	durations := make([]time.Duration, iterations)

	for i := 0; i < iterations; i++ {
		iterStart := time.Now()
		fn()
		durations[i] = time.Since(iterStart)
	}

	totalTime := time.Since(start)
	avgTime := totalTime / time.Duration(iterations)

	// 计算最小值和最大值
	minTime := durations[0]
	maxTime := durations[0]
	for _, d := range durations {
		if d < minTime {
			minTime = d
		}
		if d > maxTime {
			maxTime = d
		}
	}

	// 计算标准差
	var variance float64
	for _, d := range durations {
		diff := float64(d - avgTime)
		variance += diff * diff
	}
	stdDev := time.Duration(0)
	if iterations > 1 {
		stdDev = time.Duration(variance / float64(iterations-1))
	}

	return BenchmarkResult{
		Name:         name,
		Iterations:   iterations,
		TotalTime:    totalTime,
		AvgTime:      avgTime,
		MinTime:      minTime,
		MaxTime:      maxTime,
		StdDeviation: stdDev,
		Throughput:   float64(iterations) / totalTime.Seconds(),
	}
}
