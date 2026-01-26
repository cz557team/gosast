package core

import (
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
)

// ObjectPool 对象池
type ObjectPool struct {
	pool     sync.Pool
	newFunc  func() interface{}
	resetFunc func(interface{})
}

// NewObjectPool 创建对象池
func NewObjectPool(newFunc func() interface{}, resetFunc func(interface{})) *ObjectPool {
	return &ObjectPool{
		pool: sync.Pool{
			New: newFunc,
		},
		newFunc:  newFunc,
		resetFunc: resetFunc,
	}
}

// Get 获取对象
func (op *ObjectPool) Get() interface{} {
	obj := op.pool.Get()
	if obj == nil {
		obj = op.newFunc()
	}
	return obj
}

// Put 归还对象
func (op *ObjectPool) Put(obj interface{}) {
	if op.resetFunc != nil {
		op.resetFunc(obj)
	}
	op.pool.Put(obj)
}

// BytesPool 字节切片池
var BytesPool = NewObjectPool(
	func() interface{} {
		return make([]byte, 0, 64) // 预分配64字节
	},
	func(obj interface{}) {
		if bytes, ok := obj.([]byte); ok {
			for i := range bytes {
				bytes[i] = 0
			}
			bytes = bytes[:0]
		}
	},
)

// IntSlicePool 整数切片池
var IntSlicePool = NewObjectPool(
	func() interface{} {
		return make([]int, 0, 16) // 预分配16个整数
	},
	func(obj interface{}) {
		if ints, ok := obj.([]int); ok {
			ints = ints[:0]
		}
	},
)

// StringSlicePool 字符串切片池
var StringSlicePool = NewObjectPool(
	func() interface{} {
		return make([]string, 0, 16) // 预分配16个字符串
	},
	func(obj interface{}) {
		if strings, ok := obj.([]string); ok {
			strings = strings[:0]
		}
	},
)

// NodeSlicePool AST节点切片池
var NodeSlicePool = NewObjectPool(
	func() interface{} {
		return make([]*sitter.Node, 0, 32) // 预分配32个节点
	},
	func(obj interface{}) {
		if nodes, ok := obj.([]*sitter.Node); ok {
			nodes = nodes[:0]
		}
	},
)

// SymbolSlicePool 符号切片池
var SymbolSlicePool = NewObjectPool(
	func() interface{} {
		return make([]*Symbol, 0, 16) // 预分配16个符号
	},
	func(obj interface{}) {
		if symbols, ok := obj.([]*Symbol); ok {
			symbols = symbols[:0]
		}
	},
)

// CFGNodeSlicePool CFG节点切片池
var CFGNodeSlicePool = NewObjectPool(
	func() interface{} {
		return make([]*CFGNode, 0, 32) // 预分配32个CFG节点
	},
	func(obj interface{}) {
		if nodes, ok := obj.([]*CFGNode); ok {
			nodes = nodes[:0]
		}
	},
)

// BufferPool 缓冲区池
type BufferPool struct {
	pool   sync.Pool
	logger func(string)
}

// NewBufferPool 创建缓冲区池
func NewBufferPool(bufferSize int, logger func(string)) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, bufferSize)
			},
		},
		logger: logger,
	}
}

// Get 获取缓冲区
func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

// Put 归还缓冲区
func (bp *BufferPool) Put(buf []byte) {
	bp.pool.Put(buf)
}

// BytesBuffer 字节缓冲区管理
type BytesBuffer struct {
	data []byte
	pos  int
}

// NewBytesBuffer 创建新的字节缓冲区
func NewBytesBuffer(size int) *BytesBuffer {
	return &BytesBuffer{
		data: BytesPool.Get().([]byte),
		pos:  0,
	}
}

// Write 写入数据
func (bb *BytesBuffer) Write(p []byte) (n int, err error) {
	// 确保有足够的空间
	required := bb.pos + len(p)
	if required > cap(bb.data) {
		// 扩容（2倍增长）
		newCap := cap(bb.data) * 2
		if newCap < required {
			newCap = required
		}
		newData := make([]byte, newCap)
		copy(newData, bb.data[:bb.pos])
		BytesPool.Put(bb.data)
		bb.data = newData
	}

	n = copy(bb.data[bb.pos:], p)
	bb.pos += n
	return n, nil
}

// Bytes 返回缓冲区的字节切片
func (bb *BytesBuffer) Bytes() []byte {
	return bb.data[:bb.pos]
}

// Reset 重置缓冲区
func (bb *BytesBuffer) Reset() {
	bb.pos = 0
}

// Release 释放缓冲区
func (bb *BytesBuffer) Release() {
	BytesPool.Put(bb.data)
	bb.data = nil
	bb.pos = 0
}

// PooledSlicePool 池化切片池
type PooledSlicePool struct {
	elemSize int
	pool     sync.Pool
}

// NewPooledSlicePool 创建池化切片池
func NewPooledSlicePool(elemSize int) *PooledSlicePool {
	return &PooledSlicePool{
		elemSize: elemSize,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, elemSize)
			},
		},
	}
}

// Get 获取切片
func (psp *PooledSlicePool) Get() []byte {
	return psp.pool.Get().([]byte)
}

// Put 归还切片
func (psp *PooledSlicePool) Put(s []byte) {
	for i := range s {
		s[i] = 0
	}
	s = s[:0]
	psp.pool.Put(s)
}

// Prewarm 预热池
func (psp *PooledSlicePool) Prewarm(count int) {
	for i := 0; i < count; i++ {
		psp.pool.Put(psp.pool.New())
	}
}
