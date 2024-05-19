#include <iostream>
#include <map>
#include <functional>
#include <string>

class Base 
{
public:
    virtual const std::map<std::string, std::function<void()>>& getFunctionMap() const = 0;
};

class DerivedA : public Base 
{
public:
    static std::map<std::string, std::function<void()>>& getFunctionMapStatic() 
    {
        static std::map<std::string, std::function<void()>> functionMap = {
            {"task1", []() { std::cout << "DerivedA: task1\n"; }},
            {"task2", []() { std::cout << "DerivedA: task2\n"; }}
        };
        return functionMap;
    }

    const std::map<std::string, std::function<void()>>& getFunctionMap() const override 
    {
        return getFunctionMapStatic();
    }
};

class DerivedB : public Base 
{
public:
    static std::map<std::string, std::function<void()>>& getFunctionMapStatic() 
    {
        static std::map<std::string, std::function<void()>> functionMap = {
            {"task1", []() { std::cout << "DerivedB: task1\n"; }},
            {"task3", []() { std::cout << "DerivedB: task3\n"; }}
        };
        return functionMap;
    }

    const std::map<std::string, std::function<void()>>& getFunctionMap() const override 
    {
        return getFunctionMapStatic();
    }
};

int main() 
{
    DerivedA a;
    DerivedB b;

    auto& functionMapA = a.getFunctionMap();
    auto& functionMapB = b.getFunctionMap();

    functionMapA.at("task1")();
    functionMapA.at("task2")();
    
    functionMapB.at("task1")();
    functionMapB.at("task3")();

    return 0;
}