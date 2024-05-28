#include <iostream>
#include <string>
#include <tuple>
#include <initializer_list>
#include <concepts>

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

struct BaseWrapper {};

template <typename Type, typename T>
struct Wrapper : public BaseWrapper
{
    T value;

    Wrapper(T& v) : value(v) { }

    void init()
    {
        value = Type::get();
    }
};

template <typename T>
concept IsWrapper = std::is_base_of<BaseWrapper, T>::value;

template <IsWrapper Wrapper>
void init(Wrapper wr)
{
    // std::cout << typeid(PackType).name() << ": " << obj << "/" << type.get() << std::endl;
    wr.init();
    // std::cout << typeid(PackType).name() << ": " << obj << "/" << type.get() << std::endl;
}

void inits() {}

template <IsWrapper wrapper, typename... args>
void inits(wrapper& wr, args&&... v)
{
    init(wr);
    inits(v...);
}

template <typename PackType, typename ObjType, typename... args>
void inits(PackType type, ObjType& obj, args&&... v)
{
    
    init(type, obj);
    inits(v...);
}



template <typename Type, typename T>
static inline Wrapper<Type, T&> Using(T&& v)
{
    return Wrapper<Type, T&>(v);
};

int main()
{

    int i {0};
    float f {0};
    std::cout << i << std::endl;
    std::cout << f << std::endl;

    inits(INT{}, i, Using<FLOAT>(f));
    // inits2({INT{}, i}, {FLOAT{}, f});

    std::cout << "####" << std::endl;
    std::cout << i << std::endl;
    std::cout << f << std::endl;
}