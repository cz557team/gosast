/**
 * Sample ID: VULN_CPP_833_DEADLOCK
 * CWE: 833 (Deadlock)
 * Description: 两个线程以相反的顺序获取两个互斥锁
 */

#include <thread>
#include <mutex>
#include <chrono>

std::mutex m1;
std::mutex m2;

void threadA() {
    std::lock_guard<std::mutex> lg1(m1);
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // 增加死锁概率
    std::lock_guard<std::mutex> lg2(m2); // 等待 m2
}

void threadB() {
    std::lock_guard<std::mutex> lg1(m2);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::lock_guard<std::mutex> lg2(m1); // 等待 m1
}

int main() {
    std::thread t1(threadA);
    std::thread t2(threadB);
    t1.join();
    t2.join();
    return 0;
}

// 修复版本 - 使用 std::lock 同时获取多个锁
void safe_threadA() {
    std::lock(m1, m2); // 同时获取两个锁
    std::lock_guard<std::mutex> lg1(m1, std::adopt_lock);
    std::lock_guard<std::mutex> lg2(m2, std::adopt_lock);
}

void safe_threadB() {
    std::lock(m1, m2); // 相同的锁顺序
    std::lock_guard<std::mutex> lg1(m1, std::adopt_lock);
    std::lock_guard<std::mutex> lg2(m2, std::adopt_lock);
}
