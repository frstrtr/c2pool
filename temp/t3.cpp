#include <iostream>
#include <map>
#include <functional>
#include <string>

#include <core/common.hpp>

template <typename T>
class Base 
{
public:
    virtual const std::map<std::string, std::function<void(T*)>>& getFunctionMap() const = 0;

    void invoke(std::string name) const
    {
        T* p = const_cast<T*>(static_cast<const T*>(this));
        getFunctionMap().at(name)(p);
    }
};

class DerivedA : public Base<DerivedA> 
{
public:
    static std::map<std::string, std::function<void(DerivedA*)>>& getFunctionMapStatic() 
    {
        static std::map<std::string, std::function<void(DerivedA*)>> functionMap = {
            {"task1", [&](DerivedA* v) { v->task1(); }},
            {"task2", [&](DerivedA* v) { v->task2(); }}
        };
        return functionMap;
    }

    const std::map<std::string, std::function<void(DerivedA*)>>& getFunctionMap() const override {
        return getFunctionMapStatic();
    }

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
};

// Тестирование
int main() 
{
    DerivedA a;

    auto& functionMapA = a.getFunctionMap();

    auto begin = c2pool::debug_timestamp();
    for (int i = 0; i < 100'000; i++)
    {
        a.invoke("task1");
    }
    auto finish = c2pool::debug_timestamp();
    std::cout << finish-begin << std::endl;

    std::cout << a.i << std::endl;

    return 0;
}