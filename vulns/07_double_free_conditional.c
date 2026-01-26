/**
 * Sample ID: VULN_C_415_CONDITIONAL
 * CWE: 415 (Double Free)
 * Description: 错误处理逻辑中的路径重叠导致重复释放
 */

#include <stdlib.h>

void process_data(int error_flag) {
    char *buffer = (char *)malloc(128);
    if (!buffer) return;

    if (error_flag) {
        // 处理错误
        free(buffer); // 第一次释放
        // 忘记 return，或者逻辑流继续向下执行
    }

    //... 其他逻辑...

    // VULNERABILITY: 如果 error_flag 为真，这里是第二次释放。
    // 静态分析器需探索 error_flag=true 的路径。
    free(buffer);
}

// 修复版本
void safe_process_data(int error_flag) {
    char *buffer = (char *)malloc(128);
    if (!buffer) return;

    if (error_flag) {
        // 处理错误
        free(buffer); // 第一次释放
        return; // 确保返回，避免重复释放
    }

    //... 其他逻辑...

    free(buffer);
}
