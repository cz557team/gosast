package core

import (
	"container/list"
	"context"
	"crypto/sha1"
	"fmt"
	"os"
	"sync"
	"time"
)

// CacheEntry 缓存条目
type CacheEntry struct {
	Unit       *ParseUnit
	FileHash   string    // 文件内容哈希
	ModifiedAt time.Time // 文件修改时间
	AccessTime time.Time // 最后访问时间
	RefCount   int       // 引用计数
}

// OptimizedFileCache 优化的文件缓存
type OptimizedFileCache struct {
	cache     map[string]*CacheEntry
	lruList   *list.List // LRU列表
	maxSize   int        // 最大缓存条目数
	maxMemory int64      // 最大内存使用（字节）
	currentMemory int64  // 当前内存使用
	ctx       context.Context
	mutex     sync.RWMutex
	stats     CacheStats
}

// CacheStats 缓存统计信息
type CacheStats struct {
	Hits      int           `json:"hits"`
	Misses    int           `json:"misses"`
	Evictions int           `json:"evictions"`
	MemoryUsed int64        `json:"memory_used"`
	AvgAccessTime time.Duration `json:"avg_access_time"`
}

// NewOptimizedFileCache 创建优化的文件缓存
func NewOptimizedFileCache(ctx context.Context, maxSize int, maxMemory int64) *OptimizedFileCache {
	return &OptimizedFileCache{
		cache:     make(map[string]*CacheEntry),
		lruList:   list.New(),
		maxSize:   maxSize,
		maxMemory: maxMemory,
		ctx:       ctx,
	}
}

// Get 获取缓存条目
func (ofc *OptimizedFileCache) Get(filePath string) (*ParseUnit, error) {
	ofc.mutex.RLock()
	entry, exists := ofc.cache[filePath]
	ofc.mutex.RUnlock()

	if !exists {
		ofc.stats.Misses++
		return ofc.loadAndCache(filePath)
	}

	// 检查文件是否已修改
	if ofc.isFileModified(entry, filePath) {
		ofc.mutex.Lock()
		delete(ofc.cache, filePath)
		ofc.currentMemory -= ofc.estimateSize(entry.Unit)
		ofc.lruList.Remove(ofc.getLRUEntry(filePath))
		ofc.mutex.Unlock()

		ofc.stats.Misses++
		return ofc.loadAndCache(filePath)
	}

	// 更新LRU
	ofc.updateLRU(filePath)

	// 增加引用计数
	ofc.mutex.Lock()
	entry.RefCount++
	entry.AccessTime = time.Now()
	ofc.mutex.Unlock()

	ofc.stats.Hits++
	return entry.Unit, nil
}

// Put 归还缓存条目
func (ofc *OptimizedFileCache) Put(filePath string) {
	ofc.mutex.RLock()
	entry, exists := ofc.cache[filePath]
	ofc.mutex.RUnlock()

	if !exists {
		return
	}

	ofc.mutex.Lock()
	entry.RefCount--
	if entry.RefCount <= 0 {
		// 可以考虑主动清理长时间未使用的条目
	}
	ofc.mutex.Unlock()
}

// loadAndCache 加载并缓存文件
func (ofc *OptimizedFileCache) loadAndCache(filePath string) (*ParseUnit, error) {
	// 解析文件
	parsedUnit, err := ParseFile(ofc.ctx, filePath)
	if err != nil {
		return nil, err
	}

	// 计算文件哈希
	fileHash, err := ofc.calculateFileHash(filePath)
	if err != nil {
		return nil, err
	}

	// 创建ParseUnit
	unit := &ParseUnit{
		FilePath: filePath,
		Tree:     parsedUnit.Tree,
		Source:   parsedUnit.Source,
		LoadedAt: time.Now(),
		RefCount: 1,
	}

	// 提取符号信息
	unit.extractSymbols()

	// 创建缓存条目
	entry := &CacheEntry{
		Unit:       unit,
		FileHash:   fileHash,
		ModifiedAt: time.Now(),
		AccessTime: time.Now(),
		RefCount:   1,
	}

	// 缓存条目
	ofc.cacheEntry(filePath, entry)

	return unit, nil
}

// cacheEntry 缓存条目
func (ofc *OptimizedFileCache) cacheEntry(filePath string, entry *CacheEntry) {
	ofc.mutex.Lock()
	defer ofc.mutex.Unlock()

	// 检查是否需要清理缓存
	ofc.evictIfNeeded(entry.Unit)

	// 添加到缓存
	ofc.cache[filePath] = entry
	ofc.lruList.PushFront(filePath)
	ofc.currentMemory += ofc.estimateSize(entry.Unit)
}

// evictIfNeeded 必要时清理缓存
func (ofc *OptimizedFileCache) evictIfNeeded(unit *ParseUnit) {
	for ofc.shouldEvict() {
		// 获取最少使用的条目
		lastElement := ofc.lruList.Back()
		if lastElement == nil {
			break
		}

		evictFile := lastElement.Value.(string)
		evictEntry := ofc.cache[evictFile]

		// 检查引用计数
		if evictEntry.RefCount > 0 {
			// 不能驱逐，移到前面
			ofc.lruList.MoveToFront(lastElement)
			break
		}

		// 驱逐条目
		delete(ofc.cache, evictFile)
		ofc.lruList.Remove(lastElement)
		ofc.currentMemory -= ofc.estimateSize(evictEntry.Unit)
		ofc.stats.Evictions++

		if isVerbose() {
		}
	}
}

// shouldEvict 判断是否应该驱逐缓存条目
func (ofc *OptimizedFileCache) shouldEvict() bool {
	return len(ofc.cache) >= ofc.maxSize ||
		ofc.currentMemory >= ofc.maxMemory
}

// updateLRU 更新LRU
func (ofc *OptimizedFileCache) updateLRU(filePath string) {
	ofc.mutex.Lock()
	defer ofc.mutex.Unlock()

	if elem := ofc.getLRUEntry(filePath); elem != nil {
		ofc.lruList.MoveToFront(elem)
	}
}

// getLRUEntry 获取LRU条目
func (ofc *OptimizedFileCache) getLRUEntry(filePath string) *list.Element {
	for e := ofc.lruList.Front(); e != nil; e = e.Next() {
		if e.Value.(string) == filePath {
			return e
		}
	}
	return nil
}

// isFileModified 检查文件是否已修改
func (ofc *OptimizedFileCache) isFileModified(entry *CacheEntry, filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return true // 如果无法获取文件信息，视为已修改
	}

	return !info.ModTime().Before(entry.ModifiedAt)
}

// calculateFileHash 计算文件哈希
func (ofc *OptimizedFileCache) calculateFileHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	hash := sha1.Sum(data)
	return fmt.Sprintf("%x", hash), nil
}

// estimateSize 估算ParseUnit的大小
func (ofc *OptimizedFileCache) estimateSize(unit *ParseUnit) int64 {
	// 估算Tree的大小
	treeSize := int64(0)
	if unit.Tree != nil {
		// Tree的结构大致估算
		treeSize = int64(unit.Tree.RootNode().EndByte())
	}

	return int64(len(unit.Source)) + treeSize + 4096 // 额外4096字节用于其他结构
}

// GetStats 获取统计信息
func (ofc *OptimizedFileCache) GetStats() map[string]interface{} {
	ofc.mutex.RLock()
	defer ofc.mutex.RUnlock()

	total := ofc.stats.Hits + ofc.stats.Misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(ofc.stats.Hits) / float64(total)
	}

	return map[string]interface{}{
		"cache_size":   len(ofc.cache),
		"hits":         ofc.stats.Hits,
		"misses":       ofc.stats.Misses,
		"hit_rate":     hitRate,
		"evictions":    ofc.stats.Evictions,
		"memory_used":  ofc.currentMemory,
		"max_memory":   ofc.maxMemory,
		"memory_usage": float64(ofc.currentMemory) / float64(ofc.maxMemory) * 100,
	}
}

// Clear 清空缓存
func (ofc *OptimizedFileCache) Clear() {
	ofc.mutex.Lock()
	defer ofc.mutex.Unlock()

	ofc.cache = make(map[string]*CacheEntry)
	ofc.lruList.Init()
	ofc.currentMemory = 0
	ofc.stats = CacheStats{}
}

// Preload 预加载文件
func (ofc *OptimizedFileCache) Preload(filePaths []string) {
	// 使用工作池并发预加载
	sem := make(chan struct{}, 4) // 限制并发数

	for _, filePath := range filePaths {
		go func(fp string) {
			sem <- struct{}{}
			_, err := ofc.Get(fp)
			if err != nil && isVerbose() {
			}
			<-sem
		}(filePath)
	}
}

// === Phase 5: 自动 Tree 释放优化 ===

// treeReleaserCtx 控制 Tree 释放 goroutine 的生命周期
var treeReleaserCtx struct {
	sync.Once
	cancel context.CancelFunc
}

// StartTreeReleaser 启动后台 Tree 释放 goroutine（Phase 5 优化）
func (ofc *OptimizedFileCache) StartTreeReleaser(idleTimeout time.Duration, interval time.Duration) {
	treeReleaserCtx.Do(func() {
		ctx, cancel := context.WithCancel(ofc.ctx)
		treeReleaserCtx.cancel = cancel

		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					ofc.ReleaseIdleTrees(idleTimeout)
				case <-ctx.Done():
					return
				}
			}
		}()
	})
}

// StopTreeReleaser 停止 Tree 释放 goroutine（Phase 5 优化）
func (ofc *OptimizedFileCache) StopTreeReleaser() {
	if treeReleaserCtx.cancel != nil {
		treeReleaserCtx.cancel()
	}
}

// ReleaseIdleTrees 释放空闲的 Tree 以节省内存（Phase 5 优化）
// idleTimeout: Tree 空闲超时时间（如 5 分钟）
// 返回释放的 Tree 数量和节省的内存（字节）
func (ofc *OptimizedFileCache) ReleaseIdleTrees(idleTimeout time.Duration) (int, int64) {
	ofc.mutex.Lock()
	defer ofc.mutex.Unlock()

	releasedCount := 0
	savedMemory := int64(0)

	for filePath, entry := range ofc.cache {
		unit := entry.Unit

		// 检查是否可以释放 Tree
		if !unit.CanReleaseTree(idleTimeout) {
			continue
		}

		// 记录释放前的 Tree 大小
		treeSize := unit.GetTreeSize()

		// 释放 Tree
		unit.ReleaseTree()

		// 更新统计
		releasedCount++
		savedMemory += treeSize

		// 更新内存统计
		ofc.currentMemory -= treeSize

		if isVerbose() {
			fmt.Printf("[Tree Release] Released tree for %s, saved %d bytes\n", filePath, treeSize)
		}
	}

	if releasedCount > 0 {
		ofc.stats.Evictions += releasedCount
		ofc.stats.MemoryUsed = ofc.currentMemory
	}

	return releasedCount, savedMemory
}

// GetTotalTreeSize 获取所有 Tree 的总内存占用（Phase 5 优化）
func (ofc *OptimizedFileCache) GetTotalTreeSize() int64 {
	ofc.mutex.RLock()
	defer ofc.mutex.RUnlock()

	totalSize := int64(0)
	for _, entry := range ofc.cache {
		totalSize += entry.Unit.GetTreeSize()
	}

	return totalSize
}

// GetReleasedTreeCount 获取已释放 Tree 的数量（Phase 5 优化）
func (ofc *OptimizedFileCache) GetReleasedTreeCount() int {
	ofc.mutex.RLock()
	defer ofc.mutex.RUnlock()

	count := 0
	for _, entry := range ofc.cache {
		if entry.Unit.TreeReleased {
			count++
		}
	}

	return count
}

