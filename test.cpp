#include <stdio.h>
#include <string.h>

// 不再提供定义，只声明
 int check(int input)
 {
    if (input == 123456) {
        return 1;
    
    }
    else {
    return 0;
    }
 }

 int main() {
  int password;
  printf("请输入密码: ");
  scanf("%d", &password);
  printf("You entered: %d\n", password);

  if (check(password)) {
    printf("Access granted.\n");
  } else {
    printf("Access denied.\n");
  }
  return 0;
}