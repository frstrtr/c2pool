#include <iostream>
#include <string>

struct INT
{
    static int get()
    {
        return 50;
    }
};

struct FLOAT
{
    static float get()
    {
        return 3.22;
    }
};

template <typename PackType, typename ObjType>
void init(PackType type, ObjType& obj)
{
    std::cout << typeid(PackType).name() << ": " << obj << "/" << type.get() << std::endl;
    obj = type.get();
    std::cout << typeid(PackType).name() << ": " << obj << "/" << type.get() << std::endl;
}

void inits() {}

template <typename PackType, typename ObjType, typename... args>
void inits(PackType type, ObjType& obj, args&&... v)
{
    
    init(type, obj);
    inits(v...);
}

int main()
{

    int i {0};
    float f {0};
    std::cout << i << std::endl;
    std::cout << f << std::endl;

    inits(INT{}, i, FLOAT{}, f);

    std::cout << "####" << std::endl;
    std::cout << i << std::endl;
    std::cout << f << std::endl;
}