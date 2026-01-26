/**
 * Sample ID: VULN_C_416_SIMPLE
 * CWE: 416 (Use After Free)
 * Description: 释放内存后再次解引用指针
 */

#include <stdlib.h>
#include <stdio.h>

void uaf_trigger() {
    int *ptr = (int *)malloc(sizeof(int));
    *ptr = 42;

    free(ptr); // 内存被释放

    // VULNERABILITY: ptr 现在是悬空指针。
    // 这种访问是未定义行为，可能导致崩溃或利用。
    printf("Value: %d\n", *ptr);
}

// 修复版本
void safe_uaf() {
    int *ptr = (int *)malloc(sizeof(int));
    *ptr = 42;

    printf("Value: %d\n", *ptr);
    free(ptr);
    ptr = NULL; // 设置为 NULL，避免悬空指针
}
