#include <iostream>
#include <functional>
#include <variant>
#include <map>
#include <string>
#include <memory>
#include <chrono>
#include <iomanip>

template <typename...T>
class MessageHandler
{
private:
    using var_t = std::variant<std::unique_ptr<T>...>;
    using handlers_t = std::map<std::string, std::function<var_t()>>;
    static handlers_t m_handlers;

    template <typename Ty>
    static void add_handlers()
    {
        Ty msg;
        m_handlers[msg.m_command] = []() { auto msg = std::make_unique<Ty>(); std::cout << msg->m_command << std::endl; return msg; };
    }

    static handlers_t init_handlers()
    {
        handlers_t handlers;
        (( add_handlers<T>() ), ...);
        return handlers;
    }

public:
    var_t parse(std::string cmd)
    {
        if (m_handlers.contains(cmd))
            return m_handlers[cmd]();
        else
            throw std::out_of_range("MessageHandler not contain " + cmd);
    }

    // template <typename Caller>
    // void call(std::string cmd, Caller& cl)
    // {
    //     std::visit([&](auto v){cl.handle(v);}, m_handlers[cmd]());
    // }
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

struct debug_timestamp
{
    std::chrono::duration<double> t;

    debug_timestamp() : t(std::chrono::high_resolution_clock::now().time_since_epoch()) { }
    debug_timestamp(std::chrono::duration<double> _t) : t(_t) {}

    debug_timestamp operator-(const debug_timestamp& v) const
    {
        return {t - v.t};
    }

    debug_timestamp operator+(const debug_timestamp& v) const
    {
        return {t + v.t};
    }

    friend std::ostream& operator<<(std::ostream &stream, const debug_timestamp& v)
    {
        stream << std::fixed << std::setprecision(10) << v.t.count() << "s";
        stream.unsetf(std::ios_base::fixed);
        return stream;
    }
};

struct CallObj
{
    MessageHandler<A, B> handler;
    int count = 1;

    void handle_message(std::string cmd)
    {
        auto result = handler.parse(cmd);
        std::visit(
            [&](auto& msg)
            {
                handle(std::move(msg), 2);
            }, result);
    }

    void handle(std::unique_ptr<A> a, int i) { count++;/*std::cout << "handle A" << i << "!\n";*/}
    void handle(std::unique_ptr<B> b, int i) { count--;/*std::cout << "handle B" << i << "!\n";*/}
};

int main()
{
    

    std::string cmd;
    std::cin >> cmd;

    // handler.m_handlers[cmd]();
    CallObj cl;
    debug_timestamp t0;
    
    cl.handle_message(cmd);

    debug_timestamp t1;

    std::cout << (t1 - t0) << std::endl;
}