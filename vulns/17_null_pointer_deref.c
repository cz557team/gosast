/**
 * Sample ID: VULN_C_476_NULL_PTR
 * CWE: 476 (NULL Pointer Dereference)
 * Description: malloc 失败时返回 NULL，直接使用导致崩溃
 */

#include <stdlib.h>

void process_data() {
    // 请求巨大的内存，极可能失败返回 NULL
    int *data = (int *)malloc(0x7fffffff);

    // VULNERABILITY: 没有检查 if (data == NULL)
    *data = 1;

    free(data);
}

void vulnerable_file_operation() {
    FILE *file = fopen("nonexistent.txt", "r");
    // VULNERABILITY: 未检查文件是否成功打开
    char buffer[256];
    fgets(buffer, sizeof(buffer), file); // 如果 file 为 NULL 则崩溃
    fclose(file);
}

// 修复版本
void safe_process_data() {
    int *data = (int *)malloc(0x7fffffff);

    // 检查分配是否成功
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    *data = 1;
    free(data);
}

void safe_file_operation() {
    FILE *file = fopen("nonexistent.txt", "r");

    // 检查文件是否成功打开
    if (file == NULL) {
        fprintf(stderr, "Cannot open file\n");
        return;
    }

    char buffer[256];
    if (fgets(buffer, sizeof(buffer), file)) {
        printf("Read: %s\n", buffer);
    }
    fclose(file);
}
