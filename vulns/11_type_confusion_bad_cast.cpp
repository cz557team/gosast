/**
 * Sample ID: VULN_CPP_843_BAD_CAST
 * CWE: 843 (Type Confusion)
 * Description: 使用 static_cast 将基类指针错误转换为不兼容的派生类指针
 */

#include <iostream>
#include <cstdlib>

class Base { public: virtual ~Base() {} };

class Greeter : public Base {
public:
    virtual void sayHi(const char *str) {
        std::cout << "Hi: " << str << std::endl;
    }
};

class Executer : public Base {
public:
    virtual void exec(const char *cmd) {
        // 敏感函数：执行系统命令
        std::system(cmd);
    }
};

int main() {
    // 实际对象是 Executer
    Base *b_ptr = new Executer();

    // VULNERABILITY: 强制转换为 Greeter 指针。
    // 编译器允许这样做 (static_cast)，但这是语义错误的。
    Greeter *g_ptr = static_cast<Greeter*>(b_ptr);

    // 调用 sayHi。在内存布局中，Greeter 的第一个虚函数是 sayHi。
    // Executer 的第一个虚函数是 exec。
    // 如果 vtable 布局重合，这里实际上调用的是 b_ptr->exec("/bin/sh")。
    g_ptr->sayHi("/bin/sh");

    delete b_ptr;
    return 0;
}

// 修复版本 - 使用 dynamic_cast 进行安全转换
#include <typeinfo>

int safe_main() {
    Base *b_ptr = new Executer();

    // 使用 dynamic_cast 进行运行时检查
    Greeter *g_ptr = dynamic_cast<Greeter*>(b_ptr);

    if (g_ptr != nullptr) {
        g_ptr->sayHi("Hello");
    } else {
        std::cout << "Type mismatch detected" << std::endl;
    }

    delete b_ptr;
    return 0;
}
