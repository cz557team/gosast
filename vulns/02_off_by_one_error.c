/**
 * Sample ID: VULN_C_787_STACK_LOOP
 * CWE: 787 (Out-of-bounds Write)
 * Description: 循环终止条件错误导致单字节溢出 (Off-by-one)
 */

void fuckall(char *src, int len) {
  char dest[10];

  // 假设 len 已经被验证为 <= 10
  if (len > 10)
    return;

  // VULNERABILITY: 数组索引从 0 到 9。
  // 如果 len == 10，循环条件 i <= len 允许 i 执行到 10。
  // dest[10] 是越界写入。
  for (int i = 0; i <= len; i++) {
    dest[i] = src[i];
  }
}

// 修复版本
void safe_off_by_one(char *src, int len) {
  char dest[10];

  if (len > 10)
    return;

  // 正确条件：i < len 或 i <= len-1
  for (int i = 0; i < len; i++) {
    dest[i] = src[i];
  }
}
