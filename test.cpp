// ...existing code...
#include <sstream> // Required for std::ostringstream

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <type_traits>
#include <algorithm>
#include <exception>
#include <cstdlib> // For std::rand() and std::srand()
#include <ctime>   // For std::time
#include <iterator> // For std::ostream_iterator
// ANSI Color Codes
const std::string RESET_COLOR = "\033[0m";
const std::string GREEN_COLOR = "\033[32m";
const std::string RED_COLOR = "\033[31m";
const std::string YELLOW_COLOR = "\033[33m";

// Helper function to print test results with color
void print_test_result(const std::string& test_name, bool success, const std::string& expected = "", const std::string& actual = "") {
    if (success) {
        std::cout << GREEN_COLOR << "[PASS] " << test_name << RESET_COLOR << std::endl;
    } else {
        std::cout << RED_COLOR << "[FAIL] " << test_name << RESET_COLOR << std::endl;
        if (!expected.empty() || !actual.empty()) {
            std::cout << "  Expected: " << expected << std::endl;
            std::cout << "  Actual  : " << actual << std::endl;
        }
    }
}

// Custom exception classes
class MyCustomException : public std::runtime_error {
public:
    MyCustomException(const std::string& msg) : std::runtime_error(msg) {}
};

class AnotherCustomException : public std::logic_error {
public:
    AnotherCustomException(const std::string& msg) : std::logic_error(msg) {}
};

// Template function
template <typename T>
T process_data(T data) {
    if (std::is_same<T, int>::value) {
        if (reinterpret_cast<int&>(data) < 0) {
            throw MyCustomException("Negative integer processed");
        }
        reinterpret_cast<int&>(data) *= 2;
    } else if (std::is_same<T, double>::value) {
        if (reinterpret_cast<double&>(data) == 0.0) {
            throw AnotherCustomException("Zero double processed");
        }
        reinterpret_cast<double&>(data) += 1.5;
    }
    return data;
}

// Function with multiple try-catch blocks and advanced features
// Returns a string representation of data_vec for checking
std::string advanced_feature_tester_checked(int val1, double val2, const std::string& str_val, bool& exception_correctly_handled, std::string& exception_message) {
    std::ostringstream oss_vec;
    exception_correctly_handled = true; // Assume true initially
    exception_message = "No specific exception expected or caught as expected.";

    std::unique_ptr<std::vector<int>> data_vec = std::make_unique<std::vector<int>>();
    data_vec->push_back(val1);
    data_vec->push_back(val1 * val1);

    try {
        int processed_val1 = process_data(val1);
        data_vec->push_back(processed_val1);

        try {
            double processed_val2 = process_data(val2);
            (void)processed_val2; // Suppress unused variable warning if not otherwise used

            if (str_val.empty()) {
                throw std::invalid_argument("String value cannot be empty");
            }
        } catch (const AnotherCustomException& ace) {
            data_vec->push_back(777);
            exception_message = ace.what();
        } catch (const std::invalid_argument& iae) {
            data_vec->push_back(778); // Different code for this path
            exception_message = "Re-thrown from invalid_argument: " + std::string(iae.what());
            throw MyCustomException(exception_message);
        }
    } catch (const MyCustomException& mce) {
        data_vec->push_back(888);
        exception_message = mce.what();
    } catch (const std::exception& e) {
        data_vec->push_back(999);
        exception_message = e.what();
        exception_correctly_handled = false; // Generic catch might not be what was expected
    }

    for (size_t i = 0; i < data_vec->size(); ++i) {
        oss_vec << (*data_vec)[i] << (i == data_vec->size() - 1 ? "" : " ");
    }
    return oss_vec.str();
}

std::string string_manipulator_checked(std::string s1, std::string s2, bool& exception_correctly_handled, std::string& exception_message) {
    exception_correctly_handled = true;
    exception_message = "No specific exception expected or caught as expected.";
    std::string result = "";

    if (s1.length() < 3) {
        exception_message = "String s1 is too short";
        throw std::length_error(exception_message);
    }
    try {
        s1.replace(1, 2, s2);
        result = s1;
        if (s2.find('X') != std::string::npos) {
            try {
                exception_message = "Found 'X' in s2 during replacement";
                throw MyCustomException(exception_message);
            } catch (const MyCustomException& mce_inner) {
                exception_message = mce_inner.what(); // Update message with caught one
                return "INNER_X_CAUGHT_" + s1;
            }
        }
    } catch (const std::out_of_range& oor) {
        exception_message = oor.what();
        return "OOR_CAUGHT";
    }
    return result;
}

int risky_division_checked(int a, int b, bool& exception_correctly_handled, std::string& exception_message) {
    exception_correctly_handled = true;
    exception_message = "No specific exception expected or caught as expected.";
    if (b == 0) {
        exception_message = "Division by zero in risky_division";
        throw std::overflow_error(exception_message);
    }
    if (a == 13 && b == 1) {
        exception_message = "Unlucky number 13 detected";
        throw AnotherCustomException(exception_message);
    }
    return a / b;
}


int main() {
    int total_tests = 0;
    int passed_tests = 0;

    auto run_test = [&](const std::string& name, std::function<void()> test_func) {
        total_tests++;
        std::cout << YELLOW_COLOR << "===== Running Test: " << name << " =====" << RESET_COLOR << std::endl;
        test_func();
        std::cout << std::endl;
    };

    run_test("Test Case 1: advanced_feature_tester - Normal execution", [&]() {
        bool eh_ok; std::string emsg;
        std::string res = advanced_feature_tester_checked(10, 5.5, "hello", eh_ok, emsg);
        std::string expected_vec = "10 100 20";
        bool pass = eh_ok && (res == expected_vec);
        print_test_result("Advanced Tester Normal", pass, expected_vec, res);
        if(pass) passed_tests++;
    });

    run_test("Test Case 2: advanced_feature_tester - Trigger inner AnotherCustomException", [&]() {
        bool eh_ok; std::string emsg;
        std::string res = advanced_feature_tester_checked(20, 0.0, "world", eh_ok, emsg);
        std::string expected_vec = "20 400 40 777";
        std::string expected_emsg = "Zero double processed";
        bool pass = eh_ok && (res == expected_vec) && (emsg == expected_emsg);
        print_test_result("Advanced Tester Inner AnotherCustomEx", pass, "vec: " + expected_vec + ", emsg: " + expected_emsg, "vec: " + res + ", emsg: " + emsg);
        if(pass) passed_tests++;
    });

    run_test("Test Case 3: advanced_feature_tester - Trigger inner std::invalid_argument, re-thrown", [&]() {
        bool eh_ok; std::string emsg;
        std::string res = advanced_feature_tester_checked(30, 7.7, "", eh_ok, emsg);
        std::string expected_vec = "30 900 60 778 888"; // 778 for invalid_arg path, 888 for outer MyCustom catch
        std::string expected_emsg = "Re-thrown from invalid_argument: String value cannot be empty";
        bool pass = eh_ok && (res == expected_vec) && (emsg == expected_emsg);
        print_test_result("Advanced Tester Inner InvalidArg Re-thrown", pass, "vec: " + expected_vec + ", emsg: " + expected_emsg, "vec: " + res + ", emsg: " + emsg);
        if(pass) passed_tests++;
    });

    run_test("Test Case 4: advanced_feature_tester - Trigger outer MyCustomException from process_data", [&]() {
        bool eh_ok; std::string emsg;
        std::string res = advanced_feature_tester_checked(-5, 3.3, "test", eh_ok, emsg);
        std::string expected_vec = "-5 25 888";
        std::string expected_emsg = "Negative integer processed";
        bool pass = eh_ok && (res == expected_vec) && (emsg == expected_emsg);
        print_test_result("Advanced Tester Outer MyCustomEx", pass, "vec: " + expected_vec + ", emsg: " + expected_emsg, "vec: " + res + ", emsg: " + emsg);
        if(pass) passed_tests++;
    });

    run_test("Test Case 5: String manipulator normal", [&]() {
        bool eh_ok = false; std::string emsg; std::string res_str;
        std::string expected_res_str = "a12def";
        std::string expected_emsg = "No specific exception expected or caught as expected.";
        try {
            res_str = string_manipulator_checked("abcdef", "12", eh_ok, emsg);
            eh_ok = true; // No exception thrown is the correct behavior
        } catch (const std::exception& e) {
            emsg = e.what(); eh_ok = false;
        }
        bool pass = eh_ok && (res_str == expected_res_str) && (emsg == expected_emsg);
        print_test_result("String Manipulator Normal", pass, "res: " + expected_res_str + ", emsg: " + expected_emsg, "res: " + res_str + ", emsg: " + emsg);
        if(pass) passed_tests++;
    });

    run_test("Test Case 6: String manipulator length_error", [&]() {
        bool eh_ok = false; std::string emsg; std::string res_str;
        std::string expected_emsg = "String s1 is too short";
        try {
            res_str = string_manipulator_checked("hi", "12", eh_ok, emsg);
        } catch (const std::length_error& le) {
            emsg = le.what();
            eh_ok = (emsg == expected_emsg);
        } catch (const std::exception& e) {
            emsg = "Unexpected exception: " + std::string(e.what());
            eh_ok = false;
        }
        bool pass = eh_ok;
        print_test_result("String Manipulator Length Error", pass, "emsg: " + expected_emsg, "emsg: " + emsg);
        if(pass) passed_tests++;
    });

        run_test("Test Case 7: String manipulator inner MyCustomException", [&]() {
        bool eh_ok = false; std::string emsg; std::string res_str;
        std::string expected_res_str_part = "INNER_X_CAUGHT_fX_marks_spotd_the_X_char"; // Corrected expected string
        std::string expected_emsg = "Found 'X' in s2 during replacement";
        try {
            res_str = string_manipulator_checked("find_the_X_char", "X_marks_spot", eh_ok, emsg);
            // eh_ok should be true if the function behaves as expected (catches internally and returns specific string)
            eh_ok = (res_str == expected_res_str_part) && (emsg == expected_emsg) ;
        } catch (const std::exception& e) { // This catch block in main should ideally not be hit for this test case
            emsg = "Unexpected exception in main: " + std::string(e.what());
            eh_ok = false;
        }
        bool pass = eh_ok;
        print_test_result("String Manipulator Inner MyCustomEx", pass, "res: " + expected_res_str_part + ", emsg: " + expected_emsg, "res: " + res_str + ", emsg: " + emsg);
        if(pass) passed_tests++;
    });

    run_test("Test Case 8: Risky division normal", [&]() {
        bool eh_ok = false; std::string emsg; int res_val = 0;
        int expected_val = 20;
        std::string expected_emsg = "No specific exception expected or caught as expected.";
        try {
            res_val = risky_division_checked(100, 5, eh_ok, emsg);
            eh_ok = true; // No exception thrown
        } catch (const std::exception& e) {
            emsg = e.what(); eh_ok = false;
        }
        bool pass = eh_ok && (res_val == expected_val) && (emsg == expected_emsg);
        print_test_result("Risky Division Normal", pass, "val: " + std::to_string(expected_val) + ", emsg: " + expected_emsg, "val: " + std::to_string(res_val) + ", emsg: " + emsg);
        if(pass) passed_tests++;
    });

    run_test("Test Case 9: Risky division by zero", [&]() {
        bool eh_ok = false; std::string emsg; int res_val = 0;
        std::string expected_emsg = "Division by zero in risky_division";
        try {
            res_val = risky_division_checked(100, 0, eh_ok, emsg);
        } catch (const std::overflow_error& ofe) {
            emsg = ofe.what();
            eh_ok = (emsg == expected_emsg);
        } catch (const std::exception& e) {
            emsg = "Unexpected exception: " + std::string(e.what());
            eh_ok = false;
        }
        bool pass = eh_ok;
        print_test_result("Risky Division By Zero", pass, "emsg: " + expected_emsg, "emsg: " + emsg);
        if(pass) passed_tests++;
    });

    run_test("Test Case 10: Risky division unlucky number", [&]() {
        bool eh_ok = false; std::string emsg; int res_val = 0;
        std::string expected_emsg = "Unlucky number 13 detected";
        try {
            res_val = risky_division_checked(13, 1, eh_ok, emsg);
        } catch (const AnotherCustomException& ace) {
            emsg = ace.what();
            eh_ok = (emsg == expected_emsg);
        }
        catch (const std::exception& e) {
            emsg = "Unexpected exception: " + std::string(e.what());
            eh_ok = false;
        }
        bool pass = eh_ok;
        print_test_result("Risky Division Unlucky Number", pass, "emsg: " + expected_emsg, "emsg: " + emsg);
        if(pass) passed_tests++;
    });

    std::cout << "===== Test Summary =====" << std::endl;
    std::cout << "Total tests: " << total_tests << std::endl;
    std::cout << "Passed tests: " << passed_tests << std::endl;
    if (passed_tests == total_tests) {
        std::cout << GREEN_COLOR << "All tests passed!" << RESET_COLOR << std::endl;
    } else {
        std::cout << RED_COLOR << (total_tests - passed_tests) << " tests failed." << RESET_COLOR << std::endl;
    }

    return (passed_tests == total_tests) ? 0 : 1;
}
// ...existing code...