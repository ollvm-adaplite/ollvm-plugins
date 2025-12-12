#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cassert>

// ======================= 全局测试状态 =======================
static bool all_tests_passed = true;

// ======================= 自定义异常类 =======================
class MyCustomError : public std::runtime_error
{
public:
    explicit MyCustomError(const std::string& message)
        : std::runtime_error("自定义错误: " + message)
    {
    }
};

class ResourceAllocationException : public MyCustomError
{
public:
    explicit ResourceAllocationException(const std::string& resource_name)
        : MyCustomError("无法分配资源 '" + resource_name + "'")
    {
    }
};

class DataCorruptionException : public MyCustomError
{
public:
    explicit DataCorruptionException(const std::string& data_id)
        : MyCustomError("数据 '" + data_id + "' 已损坏")
    {
    }
};

class NetworkErrorException : public MyCustomError
{
public:
    explicit NetworkErrorException(const std::string& endpoint)
        : MyCustomError("网络连接到 '" + endpoint + "' 失败")
    {
    }
};

// ======================= 辅助函数 =======================
void validateInput(int value)
{
    if (value < 0)
    {
        throw std::invalid_argument("输入值不能为负数: " + std::to_string(value));
    }
    if (value > 1000)
    {
        throw std::out_of_range("输入值超出范围 (0-1000): " + std::to_string(value));
    }
    std::cout << "  [validateInput] 输入值 " << value << " 有效。\n";
}

void allocateMemory(size_t size_mb)
{
    if (size_mb > 500)
    {
        throw ResourceAllocationException("内存 (" + std::to_string(size_mb) + "MB)");
    }
    std::cout << "  [allocateMemory] 成功分配 " << size_mb << "MB 内存。\n";
}

void fetchDataFromNetwork(const std::string& endpoint, int attempt_count)
{
    if (attempt_count % 3 == 0)
    {
        throw NetworkErrorException(endpoint);
    }
    std::cout << "  [fetchDataFromNetwork] 成功从 " << endpoint << " 获取数据。\n";
}

// ======================= 复杂处理函数 =======================
std::string processComplexData(int id, const std::string& name, bool simulate_corruption)
{
    std::string result_data = "";
    std::cout << "--- 开始处理数据 (ID: " << id << ", Name: " << name << ") ---\n";

    try
    {
        validateInput(id);

        try
        {
            allocateMemory(id / 10 + 10);
            std::cout << "  [processComplexData] 内存分配阶段完成。\n";
        }
        catch (const ResourceAllocationException& e)
        {
            std::cerr << "  [processComplexData] 捕获到资源分配异常: " << e.what() << "\n";
            if (!(std::string(e.what()).find("无法分配资源") != std::string::npos))
            {
                all_tests_passed = false;
            }
            throw MyCustomError("处理ID " + std::to_string(id) + " 时资源分配失败。");
        }

        try
        {
            fetchDataFromNetwork("api.example.com/data/" + std::to_string(id), id);
            std::cout << "  [processComplexData] 网络数据获取阶段完成。\n";

            if (simulate_corruption && id % 2 == 0)
            {
                throw DataCorruptionException("ID-" + std::to_string(id));
            }
            result_data = "Processed_Data_for_ID_" + std::to_string(id) + "_" + name;
            std::cout << "  [processComplexData] 数据处理阶段完成。生成数据: " << result_data << "\n";
        }
        catch (const NetworkErrorException& e)
        {
            std::cerr << "  [processComplexData] 捕获到网络异常: " << e.what() << "\n";
            if (!(std::string(e.what()).find("网络连接到") != std::string::npos))
            {
                all_tests_passed = false;
            }
            std::cout << "  [processComplexData] 尝试重新连接...\n";
            fetchDataFromNetwork("backup.example.com/data/" + std::to_string(id), id + 1);
            result_data = "Processed_Data_from_Backup_for_ID_" + std::to_string(id);
            std::cout << "  [processComplexData] 成功从备份获取数据。\n";
        }
        catch (const DataCorruptionException& e)
        {
            std::cerr << "  [processComplexData] 捕获到数据损坏异常: " << e.what() << "\n";
            if (!(std::string(e.what()).find("已损坏") != std::string::npos))
            {
                all_tests_passed = false;
            }
            throw;
        }
    }
    catch (const std::invalid_argument& e)
    {
        std::cerr << "  [processComplexData] 捕获到无效参数异常 (第一层): " << e.what() << "\n";
        if (!(std::string(e.what()).find("不能为负数") != std::string::npos))
        {
            all_tests_passed = false;
        }
        throw MyCustomError("输入参数错误，无法继续处理。");
    }
    catch (const std::out_of_range& e)
    {
        std::cerr << "  [processComplexData] 捕获到超出范围异常 (第一层): " << e.what() << "\n";
        if (!(std::string(e.what()).find("超出范围") != std::string::npos))
        {
            all_tests_passed = false;
        }
        throw MyCustomError("输入值超出可接受范围。");
    }
    catch (const MyCustomError& e)
    {
        std::cerr << "  [processComplexData] 捕获到自定义错误 (第一层): " << e.what() << "\n";
        if (!(std::string(e.what()).find("自定义错误") != std::string::npos))
        {
            all_tests_passed = false;
        }
        throw;
    }
    catch (const std::exception& e)
    {
        std::cerr << "  [processComplexData] 捕获到未知标准异常 (第一层): " << e.what() << "\n";
        throw MyCustomError("处理过程中发生未知错误。");
    }

    std::cout << "--- 数据处理 (ID: " << id << ") 完成 ---\n";
    return result_data;
}

// ======================= 主函数测试 =======================
int main()
{
    std::vector<std::pair<int, std::string>> test_cases = {
            {100, "NormalCase"},
            {-50, "NegativeID"},
            {750, "LargeMemory"},
            {30, "NetworkIssue"},
            {60, "NetworkIssueAndCorruption"},
            {1200, "OutOfRange"},
            {20, "CorruptionOnly"},
            {10, "NormalCase2"}};

    for (size_t i = 0; i < test_cases.size(); ++i)
    {
        int id = test_cases[i].first;
        std::string name = test_cases[i].second;
        bool simulate_corruption = (i % 2 == 0);

        std::cout << "\n====================================================\n";
        std::cout << "测试用例 " << i + 1 << ": ID=" << id << ", Name=" << name
                  << ", 模拟损坏=" << (simulate_corruption ? "是" : "否") << "\n";
        std::cout << "====================================================\n";

        try
        {
            std::string final_result = processComplexData(id, name, simulate_corruption);
            std::cout << "主函数: 成功处理数据。最终结果: " << final_result << "\n";
        }
        catch (const MyCustomError& e)
        {
            std::cerr << "主函数: 捕获到自定义错误: " << e.what() << "\n";
            if (!(std::string(e.what()).find("自定义错误") != std::string::npos))
            {
                all_tests_passed = false;
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "主函数: 捕获到未知标准异常: " << e.what() << "\n";
            all_tests_passed = false;
        }
        catch (...)
        {
            std::cerr << "主函数: 捕获到未知类型异常。\n";
            all_tests_passed = false;
        }
        std::cout << "\n";
    }

    // ======================= 打印最终结果 =======================
    std::cout << "====================================================\n";
    if (all_tests_passed)
    {
        std::cout << "所有测试均符合预期 ✅\n";
    }
    else
    {
        std::cout << "部分测试未符合预期 ❌\n";
    }
    std::cout << "====================================================\n";

    return 0;
}
