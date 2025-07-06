#include <iostream>
#include <map>
#include <functional>
#include <string>

#include <core/common.hpp>

template <typename T>
class Base 
{
protected:
    using derived_type = T;
public:
    virtual const std::map<std::string, std::function<void(T*)>>& getFunctionMap() const = 0;

    void invoke(std::string name) const
    {
        T* p = const_cast<T*>(static_cast<const T*>(this));
        
        auto& m = getFunctionMap();
        try
        {
            auto& func = m.at(name);
            func(p);
        } catch (const std::out_of_range& ex)
        {
            std::cout << "out range" << std::endl;
        }
    }
};

#define MAKE_BASE_BEGIN                                                                       \
    static std::map<std::string, std::function<void(derived_type *)>> &getFunctionMapStatic() \
    {                                                                                         \
        static std::map<std::string, std::function<void(derived_type *)>> functionMap = {

#define MAKE_BASE_FINISH                                                                              \
        };                                                                                            \
        return functionMap;                                                                           \
    }                                                                                                 \
                                                                                                      \
    const std::map<std::string, std::function<void(derived_type *)>> &getFunctionMap() const override \
    {                                                                                                 \
        return getFunctionMapStatic();                                                                \
    }

#define MAKE_FUNC(name) {#name, [&](derived_type* v){v->name();}},

class DerivedA : public Base<DerivedA> 
{
public:
    MAKE_BASE_BEGIN

    MAKE_FUNC(task1)
    MAKE_FUNC(task2)
    MAKE_FUNC(message_test)

    MAKE_BASE_FINISH



    int i = 0;
    void task1()
    {
        i += 1;
        // std::cout << "DerivedA: task1\n";
    }

    void task2()
    {
        // std::cout << "DerivedA: task2\n";
    }

    void message_test()
    {
        std::cout << "TEST" << std::endl;
    }
};

// Тестирование
int main() 
{
    DerivedA a;

    auto begin = core::debug_timestamp();
    for (int i = 0; i < 100'000; i++)
    {
        a.invoke("task1");
    }
    auto finish = core::debug_timestamp();
    std::cout << finish-begin << std::endl;

    a.invoke("message_test");
    a.invoke("Asd"); // err: out of range
    std::cout << a.i << std::endl;

    return 0;
}