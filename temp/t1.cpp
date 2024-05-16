#include <iostream>
#include <string>

class Base
{
    std::string m_name;
public:
    Base(std::string name) : m_name(name)
    {

    }
};

class A : public Base
{
public:
    A() : Base("A")
    {

    }
};

class B : public Base
{
public:
    B() : Base("B")
    {
        
    }
};

inline Base* get_value(const std::string& flag)
{
    
}

int main()
{
    std::string flag = "B";

    Base* value = get_value(flag);
}