/**
 * Sample ID: VULN_C_134_FMT_STR
 * CWE: 134 (Uncontrolled Format String)
 * Description: 用户输入直接传递给 printf
 */

#include <stdio.h>
#include <string.h>

void log_message(char *msg) {
    // VULNERABILITY: 如果 msg 包含 "%x %x %x"，栈数据将被打印。
    // 如果 msg 包含 "%n"，内存将被修改。
    printf(msg);

    // 修复: printf("%s", msg);
}

void vulnerable_syslog() {
    char buffer[100];
    fgets(buffer, sizeof(buffer), stdin);
    // VULNERABILITY: 使用用户输入作为格式字符串
    syslog(LOG_INFO, buffer);
}

// 修复版本
void safe_log_message(char *msg) {
    printf("%s", msg);
}

void safe_syslog() {
    char buffer[100];
    fgets(buffer, sizeof(buffer), stdin);
    // 安全的 syslog 调用
    syslog(LOG_INFO, "%s", buffer);
}
