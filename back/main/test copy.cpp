#include <exception>
#include <iostream>
#include <stdexcept>
#include <stdio.h>
__attribute((__annotate__(("vmf")))) int fib(int x) {
  if (x <= 1)
    return x;
  return fib(x - 1) + fib(x - 2);
}

int matherr(int x, int y) {
  if (y == 0) {
    throw "Division by zero"; // 抛出异常
  }
  if (x < 0) {
    throw std::runtime_error("Negative value"); // 抛出运行时异常
  }
  if (x > 1000) {
    throw std::out_of_range("Value too large"); // 抛出范围异常
  }
  if (x == 42) {
    throw std::logic_error("Logic error"); // 抛出逻辑错误异常
  }
  return x / y; // 这个除法
}

template <typename T> void print(T value) {
  std::cout << "Value: " << value << std::endl;
}
int main() {
  int a = 5;
  int b = 3;
  int c = a + b; // 这个加法会被混淆
  print(c);
  print("Result: " + std::to_string(c * 1.2));
  int result = fib(10); // 计算斐波那契数
  printf("Fibonacci Result: %d\n", result);
  if (result > 0) {
    printf("Fibonacci is positive\n");
  } else {
    printf("Fibonacci is non-positive\n");
  }
  // 这里可以添加更多的逻辑来测试混淆效果

  try {
    int x = 10;
    int y = 0;
    int z = matherr(x, y); // 这个除法会被混淆
    printf("Math Result: %d\n", z);
  } catch (std::exception &e) {
    printf("Caught an exception: Division by zero\n");
  } catch (const char *msg) {
    printf("Caught an exception: %s\n", msg);
  } catch (...) {
    printf("Caught an unknown exception\n");
  }

  return 0;
}