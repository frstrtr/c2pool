#include <iostream>
#include <map>
#include <string>

// Шаблонная функция для добавления пары в map
template <typename T>
void add_to_map(std::map<std::string, T>& m) {}

template <typename T, typename Arg, typename... Args>
void add_to_map(std::map<std::string, T>& m, Arg&& arg, Args&&... args) 
{
    m[std::to_string(arg)] = std::forward<Arg>(arg);
    add_to_map(m, std::forward<Args>(args)...);
}

#define MAKE_MAP(...) create_map(__VA_ARGS__)

template <typename... Args>
std::map<std::string, typename std::common_type<Args...>::type> create_map(Args&&... args) 
{
    std::map<std::string, typename std::common_type<Args...>::type> m;
    add_to_map(m, std::forward<Args>(args)...);
    return m;
}

int main() 
{
    auto my_map = MAKE_MAP(1, 2, 3.5, 4, 555);
    
    for (const auto& pair : my_map) {
        std::cout << "key: " << pair.first << ", value: " << pair.second << '\n';
    }
    
    return 0;
}