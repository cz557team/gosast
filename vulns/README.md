# C/C++ 静态代码分析漏洞样本库

本目录包含 18 个标准化的 C/C++ 漏洞样本，用于测试静态应用程序安全测试（SAST）工具的检测能力。这些样本按照 `vulns/ccpp/bugs.md` 报告中的分类体系组织，涵盖了从基础到高级的各类漏洞类型。

## 样本列表

### 1. 空间内存安全违规 (Spatial Memory Safety)

| 样本文件 | CWE | 漏洞类型 | 检测难度 |
|---------|-----|---------|---------|
| 01_stack_buffer_overflow.c | 787/121 | 栈缓冲区溢出 | 中等 |
| 02_off_by_one_error.c | 787 | Off-by-One 错误 | 中等 |
| 03_heap_overflow_arithmetic.c | 122 | 堆缓冲区溢出 | 高 |
| 04_global_array_oob_read.c | 125 | 越界读取 | 中等 |

### 2. 时间内存安全违规 (Temporal Memory Safety)

| 样本文件 | CWE | 漏洞类型 | 检测难度 |
|---------|-----|---------|---------|
| 05_use_after_free_simple.c | 416 | 释放后使用 | 极高 |
| 06_lambda_capture_uaf.cpp | 416 | Lambda 捕获 UAF | 极高 |
| 07_double_free_conditional.c | 415 | 重复释放 | 高 |

### 3. 数值处理稳定性 (Arithmetic and Numeric Stability)

| 样本文件 | CWE | 漏洞类型 | 检测难度 |
|---------|-----|---------|---------|
| 08_integer_overflow_buffer.c | 190 | 整数溢出 | 中等 |
| 09_integer_underflow.cpp | 191 | 整数下溢 | 中等 |
| 10_signed_unsigned_compare.cpp | 438 | 有符号/无符号比较 | 高 |

### 4. 类型系统与对象模型违规 (Type System Violations)

| 样本文件 | CWE | 漏洞类型 | 检测难度 |
|---------|-----|---------|---------|
| 11_type_confusion_bad_cast.cpp | 843 | 类型混淆 | 高 |

### 5. 并发与线程安全 (Concurrency)

| 样本文件 | CWE | 漏洞类型 | 检测难度 |
|---------|-----|---------|---------|
| 12_data_race_shared_counter.cpp | 362 | 数据竞争 | 极高 |
| 13_deadlock_ab_ba.cpp | 833 | 死锁 | 高 |
| 14_atomicity_violation.cpp | 360 | 原子性违规 | 高 |

### 6. 输入验证与注入漏洞 (Input Validation)

| 样本文件 | CWE | 漏洞类型 | 检测难度 |
|---------|-----|---------|---------|
| 15_format_string_vuln.c | 134 | 格式化字符串 | 低 |
| 16_command_injection.cpp | 78 | 命令注入 | 低 |

### 7. 资源管理错误 (Resource Management)

| 样本文件 | CWE | 漏洞类型 | 检测难度 |
|---------|-----|---------|---------|
| 17_null_pointer_deref.c | 476 | 空指针解引用 | 低/中 |
| 18_memory_leak_exception.cpp | 401 | 内存泄漏 | 中等 |

## 检测难度说明

- **低**: 简单的语法模式匹配即可检测
- **中等**: 需要基本的语义分析（污点传播、边界检查等）
- **高**: 需要跨过程分析、路径敏感分析或复杂的约束求解
- **极高**: 需要指针别名分析、流敏感分析或线程交织模拟

## 使用方法

这些样本可用于：
1. 测试 SAST 工具的检测准确性
2. 评估误报率和漏报率
3. 验证工具对不同复杂度漏洞的支持
4. 作为训练数据用于机器学习模型

每个样本文件都包含：
- 漏洞代码（阳性样本）
- 修复代码（阴性样本）
- 详细的注释说明漏洞机制

## 参考标准

- CWE (Common Weakness Enumeration)
- CERT C Secure Coding Standard
- ISO/IEC 17961:2013 C 编程语言安全编码规则
