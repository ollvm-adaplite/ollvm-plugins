
#include <sstream>  // Required for std::ostringstream

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <type_traits>
#include <algorithm>
#include <exception>
#include <cstdlib>   // For std::rand() and std::srand()
#include <ctime>     // For std::time
#include <iterator>  // For std::ostream_iterator
// ANSI Color Codes
const std::string RESET_COLOR = "\033[0m";
const std::string GREEN_COLOR = "\033[32m";
const std::string RED_COLOR = "\033[31m";
const std::string YELLOW_COLOR = "\033[33m";

// Helper function to print test results with color
void print_test_result(const std::string& test_name, bool success, const std::string& expected = "", const std::string& actual = "")
{
    if (success)
    {
        std::cout << GREEN_COLOR << "[PASS] " << test_name << RESET_COLOR << std::endl;
    }
    else
    {
        std::cout << RED_COLOR << "[FAIL] " << test_name << RESET_COLOR << std::endl;
        if (!expected.empty() || !actual.empty())
        {
            std::cout << "  Expected: " << expected << std::endl;
            std::cout << "  Actual  : " << actual << std::endl;
        }
    }
}

// Custom exception classes
class MyCustomException : public std::runtime_error
{
public:
    MyCustomException(const std::string& msg) : std::runtime_error(msg)
    {
    }
};

class AnotherCustomException : public std::logic_error
{
public:
    AnotherCustomException(const std::string& msg) : std::logic_error(msg)
    {
    }
};

// Template function
template <typename T>
T process_data(T data)
{
    if (std::is_same<T, int>::value)
    {
        if (reinterpret_cast<int&>(data) < 0)
        {
            throw MyCustomException("Negative integer processed");
        }
        reinterpret_cast<int&>(data) *= 2;
    }
    else if (std::is_same<T, double>::value)
    {
        if (reinterpret_cast<double&>(data) == 0.0)
        {
            throw AnotherCustomException("Zero double processed");
        }
        reinterpret_cast<double&>(data) += 1.5;
    }
    return data;
}

// Function with multiple try-catch blocks and advanced features
// Returns a string representation of data_vec for checking
std::string advanced_feature_tester_checked(int val1, double val2, const std::string& str_val, bool& exception_correctly_handled, std::string& exception_message)
{
    std::ostringstream oss_vec;
    exception_correctly_handled = true;  // Assume true initially
    exception_message = "No specific exception expected or caught as expected.";

    std::unique_ptr<std::vector<int>> data_vec = std::make_unique<std::vector<int>>();
    data_vec->push_back(val1);
    data_vec->push_back(val1 * val1);

    try
    {
        int processed_val1 = process_data(val1);
        data_vec->push_back(processed_val1);

        try
        {
            double processed_val2 = process_data(val2);
            (void)processed_val2;  // Suppress unused variable warning if not otherwise used

            if (str_val.empty())
            {
                throw std::invalid_argument("String value cannot be empty");
            }
        }
        catch (const AnotherCustomException& ace)
        {
            data_vec->push_back(777);
            exception_message = ace.what();
        }
        catch (const std::invalid_argument& iae)
        {
            data_vec->push_back(778);  // Different code for this path
            exception_message = "Re-thrown from invalid_argument: " + std::string(iae.what());
            throw MyCustomException(exception_message);
        }
    }
    catch (const MyCustomException& mce)
    {
        data_vec->push_back(888);
        exception_message = mce.what();
    }
    catch (const std::exception& e)
    {
        data_vec->push_back(999);
        exception_message = e.what();
        exception_correctly_handled = false;  // Generic catch might not be what was expected
    }

    for (size_t i = 0; i < data_vec->size(); ++i)
    {
        oss_vec << (*data_vec)[i] << (i == data_vec->size() - 1 ? "" : " ");
    }
    return oss_vec.str();
}





int main()
{
    int total_tests = 0;
    int passed_tests = 0;

    auto run_test = [&](const std::string& name, std::function<void()> test_func)
    {
        total_tests++;
        std::cout << YELLOW_COLOR << "===== Running Test: " << name << " =====" << RESET_COLOR << std::endl;
        test_func();
        std::cout << std::endl;
    };

    run_test("Test Case 1: advanced_feature_tester - Normal execution", [&]()
             {
        bool eh_ok; std::string emsg;
        std::string res = advanced_feature_tester_checked(10, 5.5, "hello", eh_ok, emsg);
        std::string expected_vec = "10 100 20";
        bool pass = eh_ok && (res == expected_vec);
        print_test_result("Advanced Tester Normal", pass, expected_vec, res);
        if(pass) passed_tests++; });



    std::cout << "===== Test Summary =====" << std::endl;
    std::cout << "Total tests: " << total_tests << std::endl;
    std::cout << "Passed tests: " << passed_tests << std::endl;
    if (passed_tests == total_tests)
    {
        std::cout << GREEN_COLOR << "All tests passed!" << RESET_COLOR << std::endl;
    }
    else
    {
        std::cout << RED_COLOR << (total_tests - passed_tests) << " tests failed." << RESET_COLOR << std::endl;
    }

    return (passed_tests == total_tests) ? 0 : 1;
}
