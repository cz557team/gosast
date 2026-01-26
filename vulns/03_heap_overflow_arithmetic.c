/**
 * Sample ID: VULN_C_122_HEAP_ARITHMETIC
 * CWE: 122 (Heap-based Buffer Overflow)
 * Description: 乘法溢出导致分配的内存远小于实际需求，随后发生越界写入
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void process_records(int32_t num_records) {
    // 假设每个记录 100 字节
    size_t record_size = 100;

    // VULNERABILITY: 如果 num_records 很大（例如 50,000,000 在 32位系统上），
    // num_records * 100 可能发生整数溢出 (Integer Overflow)，导致结果回绕为一个较小的值。
    // 例如：42949673 (wrap around) -> 分配了很小的内存。
    size_t alloc_size = num_records * record_size;

    char *buffer = (char *)malloc(alloc_size);
    if (!buffer) return;

    // 循环次数由原始的 num_records 控制，与实际分配大小不匹配。
    for (int32_t i = 0; i < num_records; i++) {
        // 在第 N 次迭代时，写入将超出 alloc_size 边界。
        memset(buffer + (i * record_size), 0, record_size);
    }

    free(buffer);
}

// 修复版本
void safe_process_records(int32_t num_records) {
    size_t record_size = 100;

    // 检查乘法是否会溢出
    if (num_records > 0 && record_size > SIZE_MAX / num_records) {
        // 乘法会溢出，拒绝处理
        return;
    }

    size_t alloc_size = num_records * record_size;
    char *buffer = (char *)malloc(alloc_size);
    if (!buffer) return;

    for (int32_t i = 0; i < num_records; i++) {
        memset(buffer + (i * record_size), 0, record_size);
    }

    free(buffer);
}
