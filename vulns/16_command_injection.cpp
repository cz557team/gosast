/**
 * Sample ID: VULN_CPP_78_CMD_INJECTION
 * CWE: 78 (OS Command Injection)
 * Description: 拼接字符串构建系统命令
 */

#include <cstdlib>
#include <string>
#include <iostream>

void ping_service(std::string ip) {
    // VULNERABILITY: 如果 ip 是 "127.0.0.1; rm -rf /"，则会执行删除操作。
    std::string cmd = "ping -c 1 " + ip;
    system(cmd.c_str());
}

void vulnerable_system_call() {
    char username[100];
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    // VULNERABILITY: 直接拼接用户输入
    char command[256];
    snprintf(command, sizeof(command), "id %s", username);
    system(command);
}

// 修复版本
#include <cctype>

bool is_valid_ip(const std::string& ip) {
    // 简单的 IP 格式验证
    int dots = 0;
    int nums = 0;

    for (char c : ip) {
        if (c == '.') {
            dots++;
            nums = 0;
        } else if (isdigit(c)) {
            nums++;
            if (nums > 3) return false;
        } else {
            return false; // 非数字字符
        }
    }

    return dots == 3 && nums > 0;
}

void safe_ping_service(std::string ip) {
    // 验证 IP 格式
    if (!is_valid_ip(ip)) {
        std::cerr << "Invalid IP address" << std::endl;
        return;
    }

    // 使用 execvp 避免 shell 注入
    char* args[] = {"ping", "-c", "1", (char*)ip.c_str(), NULL};
    execvp("ping", args);
}
