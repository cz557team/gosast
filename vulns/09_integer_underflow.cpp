/**
 * Sample ID: VULN_CPP_191_UNDERFLOW
 * CWE: 191 (Integer Underflow)
 * Description: 无符号变量减法导致的下溢
 */

#include <vector>
#include <iostream>

void copy_data(const std::vector<int>& src, size_t offset) {
    // 如果 offset > src.size()，例如 src.size()=10, offset=12
    // remaining 计算结果为无符号的大数 (Underflow)。
    size_t remaining = src.size() - offset;

    // VULNERABILITY: resize 尝试分配巨大的内存，可能导致 DoS 或崩溃。
    std::vector<int> dest;
    try {
        dest.resize(remaining);
        for (size_t i = 0; i < remaining; ++i) {
            // 这里还会发生越界读取 src
            dest[i] = src[offset + i];
        }
    } catch (...) {
        std::cout << "Error" << std::endl;
    }
}

// 修复版本
void safe_copy_data(const std::vector<int>& src, size_t offset) {
    if (offset >= src.size()) {
        std::cout << "Offset out of bounds" << std::endl;
        return;
    }

    size_t remaining = src.size() - offset;
    std::vector<int> dest;
    try {
        dest.resize(remaining);
        for (size_t i = 0; i < remaining; ++i) {
            dest[i] = src[offset + i];
        }
    } catch (...) {
        std::cout << "Error" << std::endl;
    }
}
