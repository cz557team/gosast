/**
 * Sample ID: VULN_CPP_416_LAMBDA
 * CWE: 416 (Use After Free)
 * Description: Lambda 捕获了局部变量的引用，但 Lambda 的执行超出了变量的生命周期
 */

#include <iostream>
#include <functional>

std::function<int()> create_closure() {
    int value = 100;
    // VULNERABILITY: 按引用捕获局部变量 'value'。
    // 当 create_closure 返回时，栈上的 'value' 被销毁。
    return [&]() {
        value = 200; // 在调用时，这里访问的是已销毁的栈内存
        return value;
    };
}

int main() {
    auto func = create_closure();
    // 调用 func 时，其内部捕获的引用指向的栈帧已失效。
    int result = func();
    std::cout << result << std::endl;
    return 0;
}

// 修复版本
std::function<int()> safe_create_closure() {
    int value = 100;
    // 使用按值捕获
    return [value]() {
        return value; // 捕获的是副本
    };
}
