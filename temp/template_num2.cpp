#include <iostream>
#include <variant>
#include <functional>
#include <map>


template <int Ver>
struct Obj
{
    constexpr static int32_t version = Ver;
};


template <typename...Objs>
struct Variants : std::variant<Objs...>
{
    using map_type = std::map<int, std::function<std::variant<Objs...>()>>;
    // using map_type = std::map<int, int>;
    // using map_type = std::map<int, std::function<int()>>;
    static map_type CreateMethods;

    static map_type init_map()
    {
        map_type some_map;
        ((some_map[Objs::version] = []{return Objs();}), ...);
        return some_map;
    }
};


template <typename... Objs>
typename Variants<Objs...>::map_type Variants<Objs...>::CreateMethods = Variants<Objs...>::init_map();

template <typename T>
void f(T value)
{
    std::cout << T::version << std::endl;
}

using check_type = Variants<Obj<1>, Obj<2>>;

int main()
{
    // std::cout << Base<15>::OpMap[15] << std::endl;
    int i;
    std::cin >> i;
    auto obj2 = check_type::CreateMethods[2]();
    // try
    // {
    //     f(std::get<Obj<2>>(obj2)); // w contains int, not float: will throw
    // }
    // catch (const std::bad_variant_access& ex)
    // {
    //     std::cout << ex.what() << '\n';
    // }
    try
    {
        std::visit([](auto&& value){f(value);}, check_type::CreateMethods[i]());        
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    // std::cout << Variants<Obj<1>, Obj<2>>::CreateMethods[i]() << std::endl;
    // std::visit([](auto& value){f(value);}, check_type::CreateMethods[i]());
}