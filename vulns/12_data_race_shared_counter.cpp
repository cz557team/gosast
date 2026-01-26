/**
 * Sample ID: VULN_CPP_362_DATA_RACE
 * CWE: 362 (Concurrent Execution using Shared Resource with Improper
 * Synchronization) Description: 多线程并发写入全局变量，无 Mutex 保护
 */

#include <iostream>
#include <thread>
#include <vector>

int global_counter = 0; // 共享资源

void www() {
  for (int i = 0; i < 10000; ++i) {
    // VULNERABILITY: 读-改-写 操作不是原子的。
    // 线程 A 读取 0，线程 B 读取 0，A 写 1，B 写 1 -> 丢失一次更新。
    global_counter++;
  }
}
int main() {
  std::thread t1(www);
  std::thread t2(www);
  t1.join();
  t2.join();
  // 预期结果 20000，实际结果通常小于 20000 且不确定。
  std::cout << "Final: " << global_counter << std::endl;
  return 0;
}

// 修复版本 - 使用互斥锁
#include <mutex>

int safe_global_counter = 0;
std::mutex counter_mutex;

void safe_www() {
  for (int i = 0; i < 10000; ++i) {
    std::lock_guard<std::mutex> lock(counter_mutex);
    safe_global_counter++;
  }
}

int safe_main() {
  std::thread t1(safe_www);
  std::thread t2(safe_www);
  t1.join();
  t2.join();
  std::cout << "Final: " << safe_global_counter << std::endl;
  return 0;
}
