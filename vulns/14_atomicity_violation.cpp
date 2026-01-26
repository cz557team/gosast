/**
 * Sample ID: VULN_CPP_360_ATOMICITY
 * CWE: 360 (Trust of System Event Data) / 362
 * Description: 虽然使用了 atomic，但在检查余额和扣款之间存在时间窗口
 */

#include <thread>
#include <atomic>
#include <chrono>

std::atomic<int> balance{100};

void withdraw(int amount) {
    // 步骤 1: 检查
    if (balance >= amount) {
        // 竞态窗口：此时可能有另一个线程修改了 balance
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        // 步骤 2: 执行
        // VULNERABILITY: 如果另一个线程在此期间扣款，balance 可能变为负数。
        balance -= amount;
    }
}

// 修复版本 - 使用 compare_exchange_weak 进行原子检查和更新
void safe_withdraw(int amount) {
    int current_balance = balance.load();
    while (current_balance >= amount) {
        // 尝试原子更新
        if (balance.compare_exchange_weak(current_balance, current_balance - amount)) {
            return; // 成功
        }
        // 如果失败，重新读取 current_balance
    }
}
