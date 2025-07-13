#include <stdio.h>

/*
 * 这是我们用来替换原始 check 函数的 "hook" 函数。
 * 它具有与原始函数完全相同的名称和签名。
 */
int check(int input) {
    // 打印一条消息，表明我们的 hook 函数被调用了。
    printf("\n--- HOOKED ---\n");
    printf("[HOOK] Function 'check' has been hijacked!\n");
    printf("[HOOK] Bypassing password check and granting access.\n");
    printf("--- END HOOK ---\n\n");

    // 无论输入什么，都返回 1，模拟绕过密码检查。
    return 1;
}