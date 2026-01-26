/**
 * Sample ID: VULN_C_787_STACK_BASIC
 * CWE: 787 (Out-of-bounds Write) -> 121 (Stack-based Buffer Overflow)
 * Description: 使用不安全的 strcpy 函数将未检查长度的输入复制到定长栈缓冲区
 */

#include <stdio.h>
#include <string.h>

void vulnerable_stack_copy(char *user_input) {
    char buffer[64]; // 栈上分配 64 字节

    // VULNERABILITY: strcpy 不检查源字符串长度。
    // 如果 user_input 长度超过 63 字符（加 null 终止符），将发生溢出。
    // 静态分析器应检测到 tainted 数据流入 sink 点 strcpy 且未做边界检查。
    strcpy(buffer, user_input);

    printf("Copied content: %s\n", buffer);
}

// 修复样本 (Negative Case)
void safe_stack_copy(char *user_input) {
    char buffer[64];
    // 使用 strncpy 并确保 null 终止，或使用 snprintf
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}
