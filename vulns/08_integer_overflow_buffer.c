/**
 * Sample ID: VULN_C_190_TO_BUFFER_OVERFLOW
 * CWE: 190 (Integer Overflow) -> 122 (Heap Buffer Overflow)
 * Description: 乘法溢出导致 malloc 参数变小，后续拷贝导致堆溢出
 */

#include <stdio.h>
#include <stdlib.h>

void setup_grid(int width, int height) {
    // 假设 width = 65536, height = 65536 (在 32 位 int 系统上)
    // 乘积 = 4,294,967,296
    // 如果 int 是 32 位，这将溢出为 0。
    int size = width * height;

    // VULNERABILITY: 分配了 0 字节（或非常小的字节）。
    int *grid = (int *)malloc(size * sizeof(int));

    if (grid) {
        // 循环尝试初始化大量数据，立即导致堆溢出。
        for (int i = 0; i < width * height; i++) {
            grid[i] = 1;
        }
        free(grid);
    }
}

// 修复版本
void safe_setup_grid(int width, int height) {
    // 检查乘法是否会溢出
    if (width <= 0 || height <= 0) {
        return;
    }

    long long total_size = (long long)width * height;
    if (total_size > SIZE_MAX / sizeof(int)) {
        fprintf(stderr, "Size too large\n");
        return;
    }

    int *grid = (int *)malloc(total_size * sizeof(int));
    if (grid) {
        for (int i = 0; i < width * height; i++) {
            grid[i] = 1;
        }
        free(grid);
    }
}
