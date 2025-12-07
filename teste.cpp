#include <iostream>

int check(int val,int passwd)
{
    if (val == passwd)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int main()
{
    int input = 0;
    std::cin >> input;
    if (check(input, 123456))
    {
        std::cout << "OK";
    }
    else
    {
        std::cout << "FAIL";
    }
}