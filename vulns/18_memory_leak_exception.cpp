/**
 * Sample ID: VULN_CPP_401_LEAK
 * CWE: 401 (Missing Release of Memory)
 * Description: 抛出异常时跳过了 delete 语句
 */

#include <iostream>
#include <stdexcept>

void risky_function() {
    int *ptr = new int;

    //... 一些操作...
    if (true) {
        // VULNERABILITY: 抛出异常，栈展开时 ptr 指针被销毁，
        // 但堆内存未释放。delete ptr 永远不会执行。
        throw std::runtime_error("Error");
    }

    delete ptr;
}

// 修复版本 - 使用 RAII
void safe_risky_function() {
    // 使用智能指针或 RAII
    std::unique_ptr<int> ptr = std::make_unique<int>();

    if (true) {
        throw std::runtime_error("Error");
        // unique_ptr 自动释放内存
    }
}

// 或者使用作用域进行 RAII
void safe_risky_function_v2() {
    int *ptr = new int;
    try {
        if (true) {
            throw std::runtime_error("Error");
        }
        //... 其他操作 ...
        delete ptr;
    } catch (...) {
        delete ptr;
        throw; // 重新抛出异常
    }
}
