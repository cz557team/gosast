package core

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Job 任务接口
type Job interface {
	ID() string
	Run() error
}

// WorkerPool 工作池
type WorkerPool struct {
	jobCh     chan Job
	resultsCh chan Result
	workers   int
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	stats     PoolStats
	running   int64
}

// Result 任务结果
type Result struct {
	JobID string
	Error error
}

// PoolStats 工作池统计信息
type PoolStats struct {
	JobsSubmitted    int64         `json:"jobs_submitted"`
	JobsCompleted    int64         `json:"jobs_completed"`
	JobsFailed       int64         `json:"jobs_failed"`
	ActiveWorkers    int64         `json:"active_workers"`
	TotalExecTimeNs  int64         `json:"total_exec_time_ns"` // 存储为纳秒
	AvgExecTime      time.Duration `json:"avg_exec_time"`
	QueueDepth       int64         `json:"queue_depth"`
	MaxQueueDepth    int64         `json:"max_queue_depth"`
	mutex            sync.Mutex
}

// NewWorkerPool 创建工作池
func NewWorkerPool(ctx context.Context, workers int, queueSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(ctx)

	pool := &WorkerPool{
		jobCh:     make(chan Job, queueSize),
		resultsCh: make(chan Result, queueSize),
		workers:   workers,
		ctx:       ctx,
		cancel:    cancel,
	}

	return pool
}

// Start 启动工作池
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
}

// worker 工作协程
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for {
		select {
		case job := <-wp.jobCh:
			atomic.AddInt64(&wp.stats.ActiveWorkers, 1)
			startTime := time.Now()

			err := job.Run()
			execTime := time.Since(startTime)

			// 更新统计
			atomic.AddInt64(&wp.stats.JobsCompleted, 1)
			atomic.AddInt64(&wp.stats.TotalExecTimeNs, int64(execTime))

			if err != nil {
				atomic.AddInt64(&wp.stats.JobsFailed, 1)
			}

			// 计算平均执行时间
			completed := atomic.LoadInt64(&wp.stats.JobsCompleted)
			totalTimeNs := atomic.LoadInt64(&wp.stats.TotalExecTimeNs)
			if completed > 0 {
				wp.stats.AvgExecTime = time.Duration(totalTimeNs) / time.Duration(completed)
			}

			atomic.AddInt64(&wp.stats.ActiveWorkers, -1)

			// 发送结果
			select {
			case wp.resultsCh <- Result{JobID: job.ID(), Error: err}:
			case <-wp.ctx.Done():
				return
			}

		case <-wp.ctx.Done():
			return
		}
	}
}

// Submit 提交任务
func (wp *WorkerPool) Submit(job Job) error {
	select {
	case wp.jobCh <- job:
		atomic.AddInt64(&wp.stats.JobsSubmitted, 1)

		// 更新队列深度
		currentDepth := int64(len(wp.jobCh))
		atomic.StoreInt64(&wp.stats.QueueDepth, currentDepth)

		// 更新最大队列深度
		wp.stats.mutex.Lock()
		if currentDepth > wp.stats.MaxQueueDepth {
			wp.stats.MaxQueueDepth = currentDepth
		}
		wp.stats.mutex.Unlock()

		return nil
	case <-wp.ctx.Done():
		return wp.ctx.Err()
	default:
		return context.DeadlineExceeded
	}
}

// GetResults 获取结果通道
func (wp *WorkerPool) GetResults() <-chan Result {
	return wp.resultsCh
}

// Stop 停止工作池
func (wp *WorkerPool) Stop() {
	wp.cancel()
	close(wp.jobCh)
	wp.wg.Wait()
	close(wp.resultsCh)
}

// Shutdown 优雅关闭
func (wp *WorkerPool) Shutdown(timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		wp.Stop()
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return context.DeadlineExceeded
	}
}

// GetStats 获取统计信息
func (wp *WorkerPool) GetStats() map[string]interface{} {
	stats := wp.stats
	stats.mutex.Lock()
	defer stats.mutex.Unlock()

	return map[string]interface{}{
		"jobs_submitted":   atomic.LoadInt64(&stats.JobsSubmitted),
		"jobs_completed":   atomic.LoadInt64(&stats.JobsCompleted),
		"jobs_failed":      atomic.LoadInt64(&stats.JobsFailed),
		"active_workers":   atomic.LoadInt64(&stats.ActiveWorkers),
		"avg_exec_time":    stats.AvgExecTime.String(),
		"queue_depth":      atomic.LoadInt64(&stats.QueueDepth),
		"max_queue_depth":  stats.MaxQueueDepth,
		"success_rate": func() float64 {
			submitted := atomic.LoadInt64(&stats.JobsSubmitted)
			if submitted == 0 {
				return 0
			}
			completed := atomic.LoadInt64(&stats.JobsCompleted)
			return float64(completed) / float64(submitted) * 100
		}(),
	}
}

// BatchJob 批量任务
type BatchJob struct {
	IDValue     string
	Jobs        []Job
	startTime   time.Time
	completed   int64
	total       int64
	mutex       sync.Mutex
	resultCh    chan Result
}

// NewBatchJob 创建批量任务
func NewBatchJob(id string, jobs []Job) *BatchJob {
	return &BatchJob{
		IDValue:     id,
		Jobs:        jobs,
		startTime:   time.Now(),
		total:       int64(len(jobs)),
		resultCh:    make(chan Result, len(jobs)),
	}
}

// ID 返回任务ID
func (bj *BatchJob) ID() string {
	return bj.IDValue
}

// Run 运行批量任务
func (bj *BatchJob) Run() error {
	for _, job := range bj.Jobs {
		go func(j Job) {
			err := j.Run()
			bj.resultCh <- Result{JobID: j.ID(), Error: err}

			// 更新进度
			atomic.AddInt64(&bj.completed, 1)
		}(job)
	}

	// 等待所有子任务完成
	for i := int64(0); i < bj.total; i++ {
		<-bj.resultCh
	}

	return nil
}

// GetProgress 获取进度
func (bj *BatchJob) GetProgress() float64 {
	if bj.total == 0 {
		return 100
	}
	return float64(atomic.LoadInt64(&bj.completed)) / float64(bj.total) * 100
}

// GetExecTime 获取执行时间
func (bj *BatchJob) GetExecTime() time.Duration {
	return time.Since(bj.startTime)
}
