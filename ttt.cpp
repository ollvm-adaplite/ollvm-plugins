#include "llvm/ADT/Optional.h"
#include <iostream>

int main() {
    llvm::Optional<int> opt = 42;
    if (opt) {
        std::cout << "Value: " << *opt << std::endl;
    } else {
        std::cout << "No value" << std::endl;
    }
    return 0;
}
