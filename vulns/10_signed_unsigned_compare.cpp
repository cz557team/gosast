/**
 * Sample ID: VULN_CPP_SIGNED_UNSIGNED_COMPARE
 * CWE: 438, 195 (Signed to Unsigned Conversion Error)
 * Description: 负数输入绕过上限检查，导致缓冲区溢出
 */

#include <vector>
#include <iostream>

void buffer_copy(int user_len) {
    char buf[100];
    // 程序员意图：防止过长拷贝。
    // 漏洞：未检查 user_len 是否为负数。

    if (user_len < sizeof(buf)) {
        // 如果 user_len 是 -1，comparison: -1 < 100 (unsigned)
        // (unsigned) -1 is 4294967295.
        // 4294967295 < 100 is FALSE.
        // 但 memcpy 接受 size_t (unsigned)，-1 变为 huge value
        // memcpy(buf, src, -1) -> copy 4GB!
    }
}

// 正确的安全版本
void safe_buffer_copy(int user_len) {
    char buf[100];
    // 检查负数和超长
    if (user_len < 0 || user_len >= sizeof(buf)) {
        return;
    }
    // 现在安全了
}

void safe_access(int index) {
    std::vector<int> data(100);

    // data.size() 返回 size_t (unsigned)。
    // 如果 index 是负数，它会被转换为巨大的 unsigned 值。
    // 检查时必须考虑这种情况
    if (index < 0 || (size_t)index >= data.size()) {
        return; // 安全检查
    }

    int value = data[index];
}
