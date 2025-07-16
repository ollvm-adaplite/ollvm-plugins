#include <iostream>
#include <stack>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <cmath>
#include <functional>
#include <vector>
#include <sstream>
#include <climits>

#define INT_MAX 2147483647

//#define DEBUG

#define NO_EXCEPTION

enum class ValueType
{
    NUMBER,
    STRING
};

class Value
{
public:
    ValueType type;
    double numberValue;
    std::string stringValue;

    Value() : type(ValueType::NUMBER), numberValue(0.0)
    {
    }  // Default constructor
    Value(double num) : type(ValueType::NUMBER), numberValue(num)
    {
    }
    Value(const std::string &str) : type(ValueType::STRING), stringValue(str)
    {
    }
};

class Token
{
public:
    enum Type
    {
        NUMBER,
        STRING,
        OPERATOR,
        FUNCTION,
        VARIABLE
    };
    Type type;
    std::string value;

    Token(Type t, const std::string &val) : type(t), value(val)
    {
    }
};

using namespace std;

std::stack<Token> operators;
std::stack<Token> temp_suffix_result;

unordered_map<string, Value> variables;  // Global container for variables

typedef struct symbol
{
    string name;
    string data;
    int typ;
    int pri;
    int pos;
    double val;
} SYMBOL;

void clear_stack(stack<Token> &s, stack<Token> &o)
{
    stack<Token> empty;
    s.swap(empty);
    stack<Token> empty2;
    o.swap(empty2);
}

/*
移除字符串中的空格
*/
string remove_spaces(string *str)
{
    str->erase(std::remove(str->begin(), str->end(), ' '), str->end());
    return *str;
}

/*
优先级map
*/
// 操作符优先级映射
std::unordered_map<std::string, int> operatorPrecedence = {
    {"&&", 4},
    {"||", 3},
    {"->", 2},
    {"<->", 1},

    {"+", 11},
    {"-", 11},
    {"*", 12},
    {"/", 12},
    {"**", 13},
    {"!", 14},
    {"==", 8},
    {"!=", 8},
    {"<", 9},
    {"<=", 9},
    {">", 9},
    {">=", 9}};

#ifdef _WIN32
#include <Windows.h>
#include <windows.h>
#endif  // _WIN32
double menu(const std::vector<double> &values)
{
#ifdef _WIN32
    // 启用 Windows 10 控制台的 ANSI 转义序列处理
    system("chcp 65001 > nul");
    SetConsoleOutputCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= 0x0004;
    SetConsoleMode(hOut, dwMode);
#endif

    std::cout << "\033[1;34m" << "====================================" << "\033[0m" << std::endl;
    std::cout << "\033[1;34m" << "          计算器功能菜单 📋         " << "\033[0m" << std::endl;
    std::cout << "\033[1;34m" << "====================================" << "\033[0m" << std::endl;

    // 数学功能
    std::cout << "\033[1;33m" << "\n数学功能 📐" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 加法 (+)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 减法 (-)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 乘法 (*)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 除法 (/)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 幂运算 (**)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 正弦函数 sin(x)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 余弦函数 cos(x)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 最大值 max(a, b, ...)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 最小值 min(a, b, ...)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 对数函数 log(value, base)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 求和函数 sum(a, b, ...)" << "\033[0m" << std::endl;
    std::cout << "\033[3;32m" << "➤ 平均值 avg(a, b, ...)" << "\033[0m" << std::endl;

    // 逻辑功能
    std::cout << "\033[1;35m" << "\n逻辑功能 🤔" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 与运算 (&&)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 或运算 (||)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 非运算 (!)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 蕴含 (->)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 等价 (<->)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 等于 (==)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 不等于 (!=)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 小于 (<)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 小于等于 (<=)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 大于 (>)" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 大于等于 (>=)" << "\033[0m" << std::endl;

    std::cout << "\033[1;33m" << "\n离散数学 📖" << "\033[0m" << std::endl;
    std::cout << "\033[3;36m" << "➤ 求真值表和范式  normal_form(string proposition,double mode) " << std::endl;
    std::cout << "\033[1;33m" << "  例如：normal_form( ( P && Q ) || ( !P && R ), 0)" << "\033[0m" << std::endl;

    std::cout << "\033[1;34m" << "\n请输入您的表达式：" << "\033[0m" << std::endl;

    return 1;
}
/*
函数名集合
*/
std::unordered_set<std::string> functions = {"max", "min", "log", "sin", "cos"};

/*
处理操作符
*/
// 处理操作符
void process_operator(const std::string &op, std::stack<Token> &operators, std::stack<Token> &temp_suffix_result)
{
    while (!operators.empty())
    {
        Token topOp = operators.top();

        // Check if the top operator is a multi-character operator and find its precedence
        if (operatorPrecedence.find(topOp.value) != operatorPrecedence.end())
        {
            int topPrecedence = operatorPrecedence[topOp.value];
            int currentPrecedence = operatorPrecedence.at(op);

            // Compare based on precedence
            if (topOp.value != "(" && topPrecedence >= currentPrecedence)
            {
                temp_suffix_result.push(topOp);
                operators.pop();
            }
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }
    operators.push(Token(Token::OPERATOR, op));
}

/*
提示函数。用于提示用户的输入是否规范，或者是否有误。
参数表：
    oriStr: 原始字符串
    Message_level: 提示等级：
        1. "error"：错误提示
        2. "warning"：警告提示
        3. "info"：信息提示
    pos: 在原始字符串中错误/警告/提示的位置
    suggestion: 提示用户可能的替代方案
*/
void Hint(string oriStr, string Message_level, size_t pos, string suggestion = "")
{
    string level_output;
    string color_code;

    // 根据提示等级设置颜色和提示类型
    if (Message_level == "error")
    {
        level_output = "\033[1;31merror\033[0m";  // 红色
        color_code = "\033[1;31m";                // 红色
    }
    else if (Message_level == "warning")
    {
        level_output = "\033[1;33mwarning\033[0m";  // 黄色
        color_code = "\033[1;33m";                  // 黄色
    }
    else if (Message_level == "info")
    {
        level_output = "\033[1;36minfo\033[0m";  // 天蓝色 (青色)
        color_code = "\033[1;36m";               // 天蓝色 (青色)
    }

    // 输出提示类型
    cout << level_output << ": at position " << pos << endl;

    // 输出带颜色的原始字符串
    cout << "        " << oriStr.substr(0, pos);               // 错误前的部分，默认颜色
    cout << color_code << oriStr.substr(pos, 1) << "\033[0m";  // 错误字符，带颜色
    cout << oriStr.substr(pos + 1) << endl;                    // 错误后面的部分，默认颜色

    // 输出指向错误字符的波浪线，长度和错误字符保持一致
    cout << "        " << string(pos, ' ') << color_code << "^";
    cout << string(oriStr.length() - pos - 1, '~') << "\033[0m" << endl;

    // 输出建议替代方案
    if (!suggestion.empty())
    {
        if (Message_level == "error")
        {
            cout << "问题:  '\e[1;31m" << suggestion << "\e[0m'" << endl;
        }
        else if (Message_level == "info")
        {
            cout << "可选的建议: '\e[1;32m" << suggestion << "\e[0m'" << endl;
        }
        else if (Message_level == "warning")
        {
            cout << "警告: '\e[1;33m" << suggestion << "\e[0m'" << endl;
        }
    }

    // 如果是 error，终止程序
    if (Message_level == "error")
    {
        clear_stack(temp_suffix_result, operators);
        throw std::invalid_argument("本轮循环因异常而终止");  // 终止当前循环
    }
}

// 定义函数类型
using OperatorFunc = std::function<double(double, double)>;
using FunctionFunc = std::function<double(double)>;
using MultiFunctionFunc = std::function<double(const std::vector<double> &)>;  // 定义 n 元函数类型

// 定义操作函数(在此添加函数后，记得去函数名map中添加对应名字)
double if_eq(double left, double right)
{
    return left == right;
}
double if_ne(double left, double right)
{
    return left != right;
}
double if_lt(double left, double right)
{
    return left < right;
}
double if_le(double left, double right)
{
    return left <= right;
}
double if_gt(double left, double right)
{
    return left > right;
}
double if_ge(double left, double right)
{
    return left >= right;
}
double Not(double left, double right)
{
    return !right;
};
double And(double left, double right)
{
    return left && right;
};
double Or(double left, double right)
{
    return left || right;
};
double implication(double left, double right)
{
    return !left || right;
};
double equivalence(double left, double right)
{
    return (!left || right) && (left || !right);
}

double add(double left, double right)
{
    return left + right;
}
double subtract(double left, double right)
{
    return left - right;
}
double multiply(double left, double right)
{
    return left * right;
}
double divide(double left, double right)
{
    if (right == 0)
    {
        clear_stack(temp_suffix_result, operators);
        throw std::invalid_argument("\033[1;31m除数不能为0\033[0m");
    }
    return left / right;
}
double power(double left, double right)
{
    return std::pow(left, right);
}

double sin_func(double x)
{
    return std::sin(x);
}
double cos_func(double x)
{
    return std::cos(x);
}

// 多元函数
double sum_func(const std::vector<double> &values)
{
    double sum = 0;
    for (double value : values)
    {
        sum += value;
    }
    return sum;
}
double avg_func(const std::vector<double> &values)
{
    double sum = 0;
    for (double value : values)
    {
        sum += value;
    }
    return sum / values.size();
}
// 定义各个多元函数
double max_func(const std::vector<double> &args)
{
    return *std::max_element(args.begin(), args.end());
}

double min_func(const std::vector<double> &args)
{
    return *std::min_element(args.begin(), args.end());
}

double log_func(const std::vector<double> &args)
{
    if (args.size() != 2)
    {
        throw std::invalid_argument("\033[1;31mlog 函数需要两个参数\033[0m");
    }
    double value = args[0];
    double base = args[1];
    if (base <= 0 || base == 1 || base <= 0)
    {
        throw std::invalid_argument("\033[1;31m非法的对数参数\033[0m");
    }
    return std::log(value) / std::log(base);
}

// 操作符映射表
std::unordered_map<std::string, OperatorFunc> operatorMap = {
    {"+", add},
    {"-", subtract},
    {"*", multiply},
    {"/", divide},
    {"**", power},
    {"==", if_eq},
    {"!=", if_ne},
    {"<", if_lt},
    {"<=", if_le},
    {">", if_gt},
    {">=", if_ge},
    {"!", Not},
    {"&&", And},
    {"||", Or},
    {"<->", equivalence},
    {"->", implication}};

// 一元函数映射表
std::unordered_map<std::string, FunctionFunc> functionMap = {
    {"sin", sin_func},
    {"cos", cos_func}};
// 多元函数映射表
std::unordered_map<std::string, MultiFunctionFunc> multiFunctionMap = {
    {"max", max_func},
    {"min", min_func},
    {"log", log_func},
    {"sum", sum_func},
    {"avg", avg_func},
    {"menu", menu}  // 示例函数名
};

// 多元函数执行器
double executeMultiFunction(const std::string &funcName, const std::vector<double> &args)
{
    auto it = multiFunctionMap.find(funcName);
    if (it != multiFunctionMap.end())
    {
        return it->second(args);
    }
    else
    {
        throw std::invalid_argument("未知的多元函数: " + funcName);
    }
}

// 操作符规范替换表
std::unordered_map<std::string, std::string> replacementMap = {
    {R"(^menu$)", "menu(1)"},
    {R"(^help$)", "menu(1)"},
    {R"(^menu\(\)$)", "menu(1)"},
    {R"(^help\(\)$)", "menu(1)"},
    {R"(^/\?$)", "menu(1)"},
    {R"(^\?$)", "menu(1)"},

};

/*
优化原始表达式，方便转化为逆波兰表达式
*/
void Expression_optimization(string *str)
{
    // 遍历字符串，查找并替换大写的函数名为小写
    for (size_t i = 0; i < str->size(); ++i)
    {
        if (isalpha(str->at(i)))
        {
            size_t start = i;
            while (i < str->size() && isalpha(str->at(i)))
            {
                ++i;
            }
            string token = str->substr(start, i - start);
            string lower_token = token;
            transform(lower_token.begin(), lower_token.end(), lower_token.begin(), ::tolower);
            if (functions.find(lower_token) != functions.end())
            {
                // 只有在函数名包含大写字母时才调用 Hint
                if (token != lower_token)
                {
                    // 提示用户并指明位置
                    Hint(*str, "info", start, lower_token);
                    str->replace(start, token.size(), lower_token);
                }
            }
        }
    }

    // 使用替换表进行替换
    for (const auto &pair : replacementMap)
    {
        std::regex pattern(pair.first);
        std::string replacement = pair.second;
        std::smatch match;
        std::string temp_str = *str;
        while (std::regex_search(temp_str, match, pattern))
        {
            size_t pos = match.position();
            Hint(*str, "info", pos, replacement);
            *str = std::regex_replace(*str, pattern, replacement);
            temp_str = *str;
        }
    }

    // 检查并添加缺失的乘号
    for (size_t i = 0; i < str->size(); ++i)
    {
        if (isdigit(str->at(i)))
        {
            // 数字与括号间
            if (i + 1 < str->size() && str->at(i + 1) == '(')
            {
                str->insert(i + 1, "*");
                Hint(*str, "info", i + 1, "*");
            }
            // 数字与变量间或数字与函数间
            if (i + 1 < str->size() && isalpha(str->at(i + 1)))
            {
                str->insert(i + 1, "*");
                Hint(*str, "info", i + 1, "*");
            }
        }
        // 括号与变量间或括号与函数间
        if (str->at(i) == ')' && i + 1 < str->size() && (isalpha(str->at(i + 1)) || str->at(i + 1) == '('))
        {
            str->insert(i + 1, "*");
            Hint(*str, "info", i + 1, "*");
        }
        // 相反括号之间
        if (str->at(i) == ')' && i + 1 < str->size() && str->at(i + 1) == '(')
        {
            str->insert(i + 1, "*");
            Hint(*str, "info", i + 1, "*");
        }
    }

    // 在单独的负数，负号前面插入0
#ifdef DEBUG
    //cout << "ori_Expression_length: " << str->size() << endl;
#endif
    for (int i = 0; i < str->size(); i++)
    {
        if (str->at(i) == '-' && (i == 0 || str->at(i - 1) == '('))
        {
            str->insert(i, "0");
        }
    }
    for (int i = 0; i < str->size(); i++)
    {
        if (str->at(i) == '!')
        {
            str->insert(i, "1");
            i++;
        }
    }

#ifdef DEBUG
    cout << "Expression_optimization: " << *str << endl;
#endif
}

// 获取操作符的最大长度
int get_max_operator_length(const std::unordered_map<std::string, int> &opMap)
{
    int maxLen = 0;
    for (const auto &pair : opMap)
    {
        maxLen = std::max(maxLen, static_cast<int>(pair.first.size()));
    }

    return maxLen;
}

int levenshteinDistance(const std::string &s1, const std::string &s2)
{
    const size_t len1 = s1.size(), len2 = s2.size();
    std::vector<std::vector<size_t>> d(len1 + 1, std::vector<size_t>(len2 + 1));

    for (size_t i = 0; i <= len1; ++i)
        d[i][0] = i;
    for (size_t i = 0; i <= len2; ++i)
        d[0][i] = i;

    for (size_t i = 1; i <= len1; ++i)
        for (size_t j = 1; j <= len2; ++j)
            d[i][j] = std::min({
                d[i - 1][j] + 1,                                    // 删除
                d[i][j - 1] + 1,                                    // 插入
                d[i - 1][j - 1] + (s1[i - 1] == s2[j - 1] ? 0 : 1)  // 替换
            });

    return d[len1][len2];
}

std::string fuzzyMatchFunction(const std::string &current,
                               const std::unordered_map<std::string, FunctionFunc> &functionMap,
                               const std::unordered_map<std::string, MultiFunctionFunc> &multiFunctionMap)
{
    std::string bestMatch;
    int bestDistance = 2147483647;

    // 遍历一元函数映射表
    for (const auto &pair : functionMap)
    {
        int distance = levenshteinDistance(current, pair.first);
        if (distance < bestDistance)
        {
            bestDistance = distance;
            bestMatch = pair.first;
        }
    }

    // 遍历多元函数映射表
    for (const auto &pair : multiFunctionMap)
    {
        int distance = levenshteinDistance(current, pair.first);
        if (distance < bestDistance)
        {
            bestDistance = distance;
            bestMatch = pair.first;
        }
    }

    return bestMatch;
}

void lexer(std::string *str)
{
    remove_spaces(str);
    int i = 0;
    bool lastWasOperatorOrOpenParenthesis = true;  // 用于跟踪上一个字符是否为操作符或 '('

    // 获取最长操作符的长度
    int maxLen = get_max_operator_length(operatorPrecedence);
#ifdef DEBUG
    std::cout << "Max operator length: " << maxLen << std::endl;
#endif

    while (i < str->size())
    {
        char current = str->at(i);

        if (isdigit(current))
        {  // 处理连续的数字
            std::string temp;
            while (i < str->size() && (isdigit(str->at(i)) || str->at(i) == '.'))
            {
                temp.push_back(str->at(i));
                i++;
            }
            temp_suffix_result.push(Token(Token::NUMBER, temp));
            lastWasOperatorOrOpenParenthesis = false;
        }
        else if (isalpha(current))
        {  // 处理变量名或函数名
            std::string temp;
            while (i < str->size() && isalnum(str->at(i)))
            {
                temp.push_back(str->at(i));
                i++;
            }
            // 处理函数名或变量名
            if (functionMap.find(temp) != functionMap.end() || multiFunctionMap.find(temp) != multiFunctionMap.end())
            {
                operators.push(Token(Token::FUNCTION, temp));
            }
            else
            {
                temp_suffix_result.push(Token(Token::VARIABLE, temp));
            }
            lastWasOperatorOrOpenParenthesis = false;
        }
        else if (current == '(')
        {
            operators.push(Token(Token::OPERATOR, "("));
            lastWasOperatorOrOpenParenthesis = true;
            i++;
        }
        else if (current == ')')
        {
            while (!operators.empty() && operators.top().value != "(")
            {
                temp_suffix_result.push(operators.top());
                operators.pop();
            }
            if (!operators.empty() && operators.top().value == "(")
            {
                operators.pop();  // 移除开括号
            }
            if (!operators.empty() && operators.top().type == Token::FUNCTION)
            {
                temp_suffix_result.push(operators.top());
                operators.pop();
            }
            lastWasOperatorOrOpenParenthesis = false;
            i++;
        }
        else if (current == ',')
        {  // 处理函数参数分隔符
            while (!operators.empty() && operators.top().value != "(")
            {
                temp_suffix_result.push(operators.top());
                operators.pop();
            }
            i++;
        }
        else if (current == '"')
        {  // 处理字符串字面量
            std::string temp;
            i++;  // 跳过起始的双引号
            while (i < str->size() && str->at(i) != '"')
            {
                temp.push_back(str->at(i));
                i++;
            }
            if (i < str->size() && str->at(i) == '"')
            {
                i++;  // 跳过结束的双引号
                temp_suffix_result.push(Token(Token::STRING, temp));
            }
            else
            {
                Hint(*str, "error", i, "缺少结束引号");
                return;
            }
            lastWasOperatorOrOpenParenthesis = false;
        }
        else
        {
            // 处理操作符
            std::string op;
            bool foundOp = false;

            for (int len = maxLen; len >= 1; --len)
            {
                if (i + len <= str->size())
                {
                    op = str->substr(i, len);
                    if (operatorPrecedence.find(op) != operatorPrecedence.end())
                    {
                        foundOp = true;
                        break;
                    }
                }
            }

            if (foundOp)
            {  // 处理操作符
                if (lastWasOperatorOrOpenParenthesis)
                {
                    if (op == "-")
                    {
                        temp_suffix_result.push(Token(Token::NUMBER, "0"));  // 在负号前加一个零
                    }
                    else if (op == "=" && op != "==")
                    {
                        clear_stack(temp_suffix_result, operators);
                        Hint(*str, "error", i, "赋值操作符 '=' 不能出现在这里");
                        return;
                    }
                    else
                    {
                        clear_stack(temp_suffix_result, operators);
                        Hint(*str, "error", i, "错误的操作符");
                        return;
                    }
                }
                process_operator(op, operators, temp_suffix_result);
                lastWasOperatorOrOpenParenthesis = false;
                i += op.length();
            }
            else
            {  // 处理未知字符
                clear_stack(temp_suffix_result, operators);
                Hint(*str, "error", i, "未知的字符");
                return;
            }
        }
    }

    while (!operators.empty())
    {
        temp_suffix_result.push(operators.top());
        operators.pop();
    }
}

// 辅助函数：从 Token 获取 Value
Value getValueFromToken(const Token &token, const string &str)
{
    if (token.type == Token::NUMBER)
    {
        return Value(std::stod(token.value));
    }
    else if (token.type == Token::STRING)
    {
        return Value(token.value);
    }
    else if (token.type == Token::VARIABLE)
    {
        auto it = variables.find(token.value);
        if (it != variables.end())
        {
            return it->second;
        }
        else
        {
            size_t pos = str.find(token.value);
            Hint(str, "error", pos != string::npos ? pos : 0, "变量 '" + token.value + "' 未定义");
            throw std::invalid_argument("变量 '" + token.value + "' 未定义");
        }
    }
    else
    {
        size_t pos = str.find(token.value);
        Hint(str, "error", pos != string::npos ? pos : 0, "无效的标记类型");
        throw std::invalid_argument("无效的标记类型");
    }
}

// 修改后的 Binary_Computing_Executor 函数
Value Binary_Computing_Executor(const Value &left, const Value &right, const std::string &op)
{
    if (op == "+")
    {
        if (left.type == ValueType::NUMBER && right.type == ValueType::NUMBER)
        {
            return Value(left.numberValue + right.numberValue);
        }
        else if (left.type == ValueType::STRING && right.type == ValueType::STRING)
        {
            return Value(left.stringValue + right.stringValue);
        }
        else
        {
            throw std::invalid_argument("类型错误: '+' 操作符要求操作数类型一致");
        }
    }
    else if (op == "==")
    {
        if (left.type == right.type)
        {
            if (left.type == ValueType::NUMBER)
            {
                return Value(left.numberValue == right.numberValue ? 1.0 : 0.0);
            }
            else if (left.type == ValueType::STRING)
            {
                return Value(left.stringValue == right.stringValue ? 1.0 : 0.0);
            }
        }
        else
        {
            return Value(0.0);  // 不同类型认为不相等
        }
    }
    else
    {
        if (left.type == ValueType::NUMBER && right.type == ValueType::NUMBER)
        {
            auto it = operatorMap.find(op);
            if (it != operatorMap.end())
            {
                double result = it->second(left.numberValue, right.numberValue);
                return Value(result);
            }
            else
            {
                throw std::invalid_argument("未知的运算符: " + op);
            }
        }
        else
        {
            throw std::invalid_argument("类型错误: 操作符 '" + op + "' 需要数值类型操作数");
        }
    }
}

double Unary_Computing_Executor(double value, const std::string func)
{
    auto it = functionMap.find(func);
    if (it != functionMap.end())
    {
        return it->second(value);
    }
    clear_stack(temp_suffix_result, operators);
    throw std::invalid_argument("未知的函数: " + func);
}

// 定义允许传入未定义变量的函数集合
std::unordered_set<std::string> neednt_args_func = {"func1", "func2"};  // 示例函数名

// 完整的 calculate 函数
Value calculate(string *str, stack<Token> temp_suffix_result)
{
    std::stack<Token> temp_result, temp_suffix;

    // 将 temp_suffix_result 逆序放入 temp_suffix 中
    while (!temp_suffix_result.empty())
    {
        temp_suffix.push(temp_suffix_result.top());
        temp_suffix_result.pop();
    }

    while (!temp_suffix.empty())
    {
        Token current = temp_suffix.top();
        temp_suffix.pop();

        if (current.type == Token::NUMBER || current.type == Token::STRING || current.type == Token::VARIABLE)
        {
            temp_result.push(current);
        }
        else if (current.type == Token::OPERATOR)
        {
            if (current.value == "=")
            {
                // 处理赋值操作符
                if (temp_result.size() < 2)
                {
                    Hint(*str, "error", str->find(current.value), "无效的表达式: 赋值缺少参数");
                    clear_stack(temp_suffix_result, operators);
                    return Value();
                }
                Token rhsToken = temp_result.top();
                temp_result.pop();
                Token lhsToken = temp_result.top();
                temp_result.pop();

                if (lhsToken.type != Token::VARIABLE)
                {
                    Hint(*str, "error", str->find(lhsToken.value), "无效的变量名");
                    clear_stack(temp_suffix_result, operators);
                    return Value();
                }
                std::string var_name = lhsToken.value;

                // 获取 RHS 的值
                Value rhsValue = getValueFromToken(rhsToken, *str);

                variables[var_name] = rhsValue;
                temp_result.push(rhsToken);  // 将 RHS 推回栈中
            }
            else
            {
                // 处理其他操作符
                if (temp_result.size() < 2)
                {
                    Hint(*str, "error", str->find(current.value), "无效的表达式: 操作符缺少参数");
                    clear_stack(temp_suffix_result, operators);
                    return Value();
                }
                Token rightToken = temp_result.top();
                temp_result.pop();
                Token leftToken = temp_result.top();
                temp_result.pop();

                Value leftValue = getValueFromToken(leftToken, *str);
                Value rightValue = getValueFromToken(rightToken, *str);

                // 执行操作并进行类型检查
                Value resultValue;
#ifndef NO_EXCEPTION
                try
                {
#endif
                    resultValue = Binary_Computing_Executor(leftValue, rightValue, current.value);
#ifndef NO_EXCEPTION
                }
                catch (const std::invalid_argument &e)
                {
                    size_t pos = str->find(current.value);
                    Hint(*str, "error", pos != string::npos ? pos : 0, e.what());
                    clear_stack(temp_suffix_result, operators);
                    return Value();
                }
#endif

                // 根据结果类型，创建相应的 Token
                if (resultValue.type == ValueType::NUMBER)
                {
                    temp_result.push(Token(Token::NUMBER, std::to_string(resultValue.numberValue)));
                }
                else if (resultValue.type == ValueType::STRING)
                {
                    temp_result.push(Token(Token::STRING, resultValue.stringValue));
                }
            }
        }
        else if (current.type == Token::FUNCTION)
        {
            // 处理函数调用
            // 检查函数是否存在
            if (functionMap.find(current.value) == functionMap.end() && multiFunctionMap.find(current.value) == multiFunctionMap.end())
            {
                size_t pos = str->find(current.value);
                Hint(*str, "error", pos != string::npos ? pos : 0, "未知的函数 '" + current.value + "'");
                clear_stack(temp_suffix_result, operators);
                return Value();
            }

            if (temp_result.empty())
            {
                Hint(*str, "error", str->find(current.value), "无效的表达式: 函数缺少参数");
                clear_stack(temp_suffix_result, operators);
                return Value();
            }

            // 获取函数参数
            std::vector<double> args;
            // 从栈中获取所有参数
            while (!temp_result.empty() && (temp_result.top().type == Token::NUMBER || temp_result.top().type == Token::VARIABLE))
            {
                Token argToken = temp_result.top();
                temp_result.pop();

                Value argValue = getValueFromToken(argToken, *str);
                if (argValue.type == ValueType::NUMBER)
                {
                    args.push_back(argValue.numberValue);
                }
                else
                {
                    Hint(*str, "error", str->find(argToken.value), "函数参数必须是数字");
                    clear_stack(temp_suffix_result, operators);
                    return Value();
                }
            }

            // 反转参数顺序，因为从栈中弹出的参数是逆序的
            std::reverse(args.begin(), args.end());

            // 检查函数类型并执行
            if (functionMap.find(current.value) != functionMap.end())
            {
                if (args.size() != 1)
                {
                    Hint(*str, "error", str->find(current.value), "函数 '" + current.value + "' 需要一个参数");
                    clear_stack(temp_suffix_result, operators);
                    return Value();
                }
                double resultValue = Unary_Computing_Executor(args[0], current.value);
                temp_result.push(Token(Token::NUMBER, std::to_string(resultValue)));
            }
            else if (multiFunctionMap.find(current.value) != multiFunctionMap.end())
            {
                double resultValue = executeMultiFunction(current.value, args);
                temp_result.push(Token(Token::NUMBER, std::to_string(resultValue)));
            }
        }
        else
        {
            Hint(*str, "error", str->find(current.value), "未知的标记类型");
            clear_stack(temp_suffix_result, operators);
            return Value();
        }
    }

    // 最终结果
    if (temp_result.size() != 1)
    {
        Hint(*str, "error", 0, "计算错误");
        return Value();
    }

    Token resultToken = temp_result.top();

    // 获取最终结果的 Value
    Value finalValue = getValueFromToken(resultToken, *str);

    return finalValue;
}

void create_variable(string var_name, string expression)
{
    if (isdigit(var_name[0]))
    {
        clear_stack(temp_suffix_result, operators);
        Hint(var_name, "error", 0, "变量名不能以数字开头");
        return;
    }

    if (functions.find(var_name) != functions.end())
    {
        clear_stack(temp_suffix_result, operators);
        Hint(var_name, "error", 0, "变量名不能与函数名重名");
        return;
    }

    lexer(&expression);
    Value result = calculate(&expression, temp_suffix_result);
    variables[var_name] = result;

    // 根据结果类型输出变量和值
    if (result.type == ValueType::NUMBER)
    {
        std::cout << var_name << " = " << result.numberValue << std::endl;
    }
    else if (result.type == ValueType::STRING)
    {
        std::cout << var_name << " = " << result.stringValue << std::endl;
    }
}
int normal_form(std::string proposition, double mode);
void executer(string *str, SYMBOL *var)
{
    Expression_optimization(str);

    // 检查是否有赋值操作 '='
    size_t equal_pos = str->find('=');
    if (equal_pos != string::npos && (equal_pos == 0 || str->at(equal_pos - 1) != '<' && str->at(equal_pos - 1) != '>' && str->at(equal_pos - 1) != '!' && str->at(equal_pos + 1) != '='))
    {
        string var_name = str->substr(0, equal_pos);
        string expression = str->substr(equal_pos + 1);

        // 去除变量名和表达式前后的空白字符
        var_name.erase(var_name.find_last_not_of(" \n\r\t") + 1);
        var_name.erase(0, var_name.find_first_not_of(" \n\r\t"));
        expression.erase(expression.find_last_not_of(" \n\r\t") + 1);
        expression.erase(0, expression.find_first_not_of(" \n\r\t"));

        // 确保变量名有效
        if (var_name.empty() || !std::isalpha(var_name[0]) || !std::all_of(var_name.begin(), var_name.end(), [](char c)
                                                                           { return std::isalnum(c) || c == '_'; }))
        {
            Hint(*str, "error", equal_pos, "executer报错：无效的变量名");
            return;
        }

        // 检查变量名是否与函数名冲突
        if (functions.find(var_name) != functions.end() || functionMap.find(var_name) != functionMap.end() || multiFunctionMap.find(var_name) != multiFunctionMap.end())
        {
            Hint(*str, "error", equal_pos, "变量名不能与函数名重名");
            return;
        }

        // 处理变量赋值
        lexer(&expression);
        Value result = calculate(&expression, temp_suffix_result);
        variables[var_name] = result;

        // 根据结果类型输出变量和值
        if (result.type == ValueType::NUMBER)
        {
            std::cout << var_name << " = " << result.numberValue << std::endl;
        }
        else if (result.type == ValueType::STRING)
        {
            std::cout << var_name << " = " << result.stringValue << std::endl;
        }
    }
    else
    {
        // 去除表达式前后的空白字符
        str->erase(str->find_last_not_of(" \n\r\t") + 1);
        str->erase(0, str->find_first_not_of(" \n\r\t"));

        // 检查是否调用了 normal_form 函数
        if (str->substr(0, 11) == "normal_form")
        {
            // 提取函数参数
            size_t start_pos = str->find("(");
            size_t end_pos = str->find_last_of(")");
            if (start_pos != string::npos && end_pos != string::npos && end_pos > start_pos)
            {
                string args_str = str->substr(start_pos + 1, end_pos - start_pos - 1);
                // 分割参数
                size_t comma_pos = args_str.find(",");
                if (comma_pos != string::npos)
                {
                    string proposition = args_str.substr(0, comma_pos);
                    string mode_str = args_str.substr(comma_pos + 1);
                    // 去除参数前后的引号和空格
                    proposition.erase(0, proposition.find_first_not_of(" \n\r\t\""));
                    proposition.erase(proposition.find_last_not_of(" \n\r\t\"") + 1);
                    mode_str.erase(0, mode_str.find_first_not_of(" \n\r\t"));
                    mode_str.erase(mode_str.find_last_not_of(" \n\r\t") + 1);
                    double mode = std::stod(mode_str);
                    // 调用 normal_form 函数
                    int result = normal_form(proposition, mode);
#ifdef DEBUG
                    std::cout << "normal_form 返回值: " << result << std::endl;
#endif
                }
                else
                {
                    std::cerr << "normal_form 函数参数错误" << std::endl;
                }
            }
            else
            {
                std::cerr << "normal_form 函数格式错误" << std::endl;
            }
        }
        else
        {
            lexer(str);
            Value result = calculate(str, temp_suffix_result);

            // 根据结果类型输出结果
            if (result.type == ValueType::NUMBER)
            {
                std::cout << result.numberValue << std::endl;
            }
            else if (result.type == ValueType::STRING)
            {
                std::cout << result.stringValue << std::endl;
            }
        }
    }

    // 清空栈
    std::stack<Token> empty;
    temp_suffix_result.swap(empty);
    std::stack<Token> empty2;
    operators.swap(empty2);
}

// 辅助函数：拼接字符串
std::string join(const std::string &separator, const std::vector<std::string> &elements)
{
    std::string result;
    for (size_t i = 0; i < elements.size(); ++i)
    {
        result += elements[i];
        if (i != elements.size() - 1)
        {
            result += separator;
        }
    }
    return result;
}
/* 添加 normal_form 函数 */
int normal_form(std::string proposition, double mode)
{
    // 提取命题变元
    std::unordered_set<std::string> vars_set;
    size_t i = 0;
    while (i < proposition.size())
    {
        if (isalpha(proposition[i]))
        {
            std::string var;
            while (i < proposition.size() && isalnum(proposition[i]))
            {
                var += proposition[i];
                i++;
            }
            vars_set.insert(var);
        }
        else
        {
            i++;
        }
    }
    std::vector<std::string> vars(vars_set.begin(), vars_set.end());
    std::sort(vars.begin(), vars.end());
    size_t n = vars.size();

    // 存储真值表
    std::vector<std::vector<bool>> truth_table;
    std::vector<bool> results;

    // 打印表头
    std::cout << "\033[1;33m";  // 黄色字体
    for (const auto &var : vars)
    {
        std::cout << var << "\t";
    }
    std::cout << proposition << "\033[0m" << std::endl;  // 重置颜色

    // 枚举所有可能的真值组合
    for (size_t i = 0; i < (1 << n); ++i)
    {
        // 设置命题变元的真值
        std::unordered_map<std::string, Value> local_variables;
        std::vector<bool> row_values;

        for (size_t j = 0; j < n; ++j)
        {
            bool value = (i >> (n - j - 1)) & 1;
            local_variables[vars[j]] = Value(value ? 1.0 : 0.0);
            row_values.push_back(value);
        }

        // 设置全局变量用于计算
        variables = local_variables;

        // 计算命题的值
        std::string temp_prop = proposition;
        clear_stack(temp_suffix_result, operators);  // 清空栈
        Expression_optimization(&temp_prop);         // 优化表达式
        lexer(&temp_prop);
        Value result;
#ifndef NO_EXCEPTION
        try
        {
#endif
            result = calculate(&temp_prop, temp_suffix_result);
#ifndef NO_EXCEPTION
        }
        catch (const std::invalid_argument &e)
        {
            // 处理计算过程中的异常
            clear_stack(temp_suffix_result, operators);
            std::cerr << e.what() << std::endl;
            return -1;
        }
#endif
        // 获取命题的真值
        bool prop_value = (result.numberValue != 0.0);
        truth_table.push_back(row_values);
        results.push_back(prop_value);

        // 判断是否需要高亮显示
        bool highlight = false;
        if (mode == 0)
        {
            // 主合取范式，命题为假时高亮
            highlight = !prop_value;
        }
        else
        {
            // 主析取范式，命题为真时高亮
            highlight = prop_value;
        }

        // 打印真值表的每一行
        if (highlight)
        {
            std::cout << "\033[42m";  // 设置绿色背景
        }

        // 打印变量的真值
        for (bool val : row_values)
        {
            if (val)
            {
                std::cout << "\033[1;32mT\033[0m\t";  // 绿色字体 T，重置字体颜色
            }
            else
            {
                std::cout << "\033[1;31mF\033[0m\t";  // 红色字体 F，重置字体颜色
            }

            if (highlight)
            {
                std::cout << "\033[42m";  // 重新设置背景色，保持背景
            }
        }

        // 打印命题的真值
        if (prop_value)
        {
            std::cout << "\033[1;32mT\033[0m";  // 绿色字体 T，重置字体颜色
        }
        else
        {
            std::cout << "\033[1;31mF\033[0m";  // 红色字体 F，重置字体颜色
        }

        if (highlight)
        {
            std::cout << "\033[0m";  // 重置所有属性
        }

        std::cout << std::endl;
    }

    // 构建范式表达式
    std::vector<std::string> clauses;
    for (size_t i = 0; i < truth_table.size(); ++i)
    {
        bool prop_value = results[i];
        if ((mode != 0 && prop_value) || (mode == 0 && !prop_value))
        {
            // 构建子句
            std::string clause;
            if (mode != 0)
            {
                // 主析取范式（PDNF）
                std::vector<std::string> literals;
                for (size_t j = 0; j < vars.size(); ++j)
                {
                    if (truth_table[i][j])
                    {
                        literals.push_back(vars[j]);
                    }
                    else
                    {
                        literals.push_back("!" + vars[j]);
                    }
                }
                clause = "( " + join(" && ", literals) + " )";
            }
            else
            {
                // 主合取范式（PCNF）
                std::vector<std::string> literals;
                for (size_t j = 0; j < vars.size(); ++j)
                {
                    if (truth_table[i][j])
                    {
                        literals.push_back("!" + vars[j]);
                    }
                    else
                    {
                        literals.push_back(vars[j]);
                    }
                }
                clause = "( " + join(" || ", literals) + " )";
            }
            clauses.push_back(clause);
        }
    }

    // 合并子句
    std::string normal_form_expr;
    if (clauses.empty())
    {
        if (mode != 0)
        {
            normal_form_expr = "0";  // 命题恒假
        }
        else
        {
            normal_form_expr = "1";  // 命题恒真
        }
    }
    else
    {
        if (mode != 0)
        {
            // 主析取范式（PDNF）
            normal_form_expr = join(" || ", clauses);
        }
        else
        {
            // 主合取范式（PCNF）
            normal_form_expr = join(" && ", clauses);
        }
    }

    std::cout << "范式表达式: " << normal_form_expr << std::endl;

    // 清空变量
    variables.clear();

    if (mode == 0)
        return 0;
    else
        return 1;
}

// 字符串化辅助宏
#define STRINGIFY_HELPER(x) #x
#define STRINGIFY(x) STRINGIFY_HELPER(x)

// 版本相关宏
#define TINY_PYTHON_VERSION "0.2"
#define TINY_PYTHON_VERSION_TAG "v0.2"
#define BUILD_HASH "hash"

// 编译器信息
#ifdef _MSC_VER
#define COMPILER "MSC"
#define COMPILER_VERSION _MSC_VER
#elif defined(__GNUC__)
#define COMPILER "GCC"
#define COMPILER_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)
#elif defined(__clang__)
#define COMPILER "Clang"
#define COMPILER_VERSION (__clang_major__ * 100 + __clang_minor__)
#else
#define COMPILER "Unknown"
#define COMPILER_VERSION 0
#endif

// 系统架构
#if defined(_WIN64)
#define ARCH "64 bit (AMD64)"
#define PLATFORM "win32"
#elif defined(_WIN32)
#define ARCH "32 bit (x86)"
#define PLATFORM "win32"
#elif defined(__x86_64__) || defined(__amd64__)
#define ARCH "64 bit (x86_64)"
#if defined(__linux__)
#define PLATFORM "linux"
#else
#define PLATFORM "unix"
#endif
#else
#define ARCH "Unknown"
#define PLATFORM "unknown"
#endif
int main()
{
#ifdef _WIN32
    system("chcp 65001 > nul");
    SetConsoleOutputCP(CP_UTF8);
#endif  // _WIN32
    bool flag = 0;
    string input_str;

    // 使用预处理宏动态生成版本信息
    printf("Tiny_Pyhon %s (tags/%s:%s, %s, %s) [%s v.%d %s] on %s\n",
           TINY_PYTHON_VERSION, TINY_PYTHON_VERSION_TAG, BUILD_HASH,
           __DATE__, __TIME__, COMPILER, COMPILER_VERSION, ARCH, PLATFORM);
    printf("Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n");

    while (1)
    {
        clear_stack(temp_suffix_result, operators);
        if (!flag)
            cout << ">>> ";
        else
            flag = 0;
        getline(cin, input_str);
        if (input_str.empty())
        {
            flag = 1;
            cout << ">>> ";
            continue;
        }
        if (input_str == "exit")
            break;
        SYMBOL var;
#ifndef NO_EXCEPTION
        try
        {
#endif
            executer(&input_str, &var);
#ifndef NO_EXCEPTION
        }
        catch (const std::invalid_argument &e)
        {
            clear_stack(temp_suffix_result, operators);
            std::cerr << e.what() << std::endl;
        }
#endif
    }

    return 0;
}