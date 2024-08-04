#include <iostream>
#include <functional>
#include <variant>
#include <map>
#include <string>

template <typename...T>
struct MessageHandler
{
    using var_t = std::variant<T...>;
    using handlers_t = std::map<std::string, std::function<var_t()>>;
    static handlers_t m_handlers;

    template <typename Ty>
    static void add_handlers()
    {
        Ty msg;
        m_handlers[msg.m_command] = [cmd = msg.m_command]() { std::cout << cmd << " type" << std::endl; var_t res = Ty(); return res; };
    }

    static handlers_t init_handlers()
    {
        handlers_t handlers;
        (( add_handlers<T>() ), ...);
        return handlers;
    }

    template <typename Caller>
    void call(std::string cmd, Caller& cl)
    {
        std::visit([&](auto v){cl.handle(v);}, m_handlers[cmd]());
    }
};

template <typename...T>
typename MessageHandler<T...>::handlers_t MessageHandler<T...>::m_handlers = MessageHandler<T...>::init_handlers();

struct Base
{
    std::string m_command;

    Base(std::string cmd) : m_command(cmd) { }
};

struct A : Base
{
    A() : Base("A") { }
};

struct B : Base
{
    B() : Base("B") { }
};

struct C : Base
{
    C() : Base("C") { }
};

struct CallObj
{
    void handle(A a) { std::cout << "handle A1!" << std::endl; }
    void handle(B a) { std::cout << "handle B2!" << std::endl; }
};

template <typename...T>
void f()
{
    // ((prt(T)), ...);
}

int main()
{
    MessageHandler<A, B> handler;

    std::string cmd;
    std::cin >> cmd;

    // handler.m_handlers[cmd]();
    CallObj cl;
    handler.call(cmd, cl);
}