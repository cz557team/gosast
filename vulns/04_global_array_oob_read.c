/**
 * Sample ID: VULN_C_125_GLOBAL_READ
 * CWE: 125 (Out-of-bounds Read)
 * Description: 缺乏对外部输入索引的验证导致读取全局数组越界
 */

#include <stdio.h>

int secret_table[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

int retrieve_value(int index) {
    // VULNERABILITY: 缺乏对 index 的上限和下限检查。
    // 如果 index 是 10 或负数，将读取无效内存。
    // 静态分析器应检测到 index 的 taint 属性未被 sanitizer 清除。
    return secret_table[index];
}

int main() {
    int val = retrieve_value(15); // 越界读取
    printf("Value: %d\n", val);
    return 0;
}

// 修复版本
int safe_retrieve_value(int index) {
    if (index < 0 || index >= 10) {
        return -1; // 错误值
    }
    return secret_table[index];
}
