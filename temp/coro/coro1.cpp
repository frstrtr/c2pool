#include <coroutine>
#include <optional>
#include <iostream>
#include <cassert>
#include <exception>

class Future;

template <typename T>
struct Promise
{
    using value_type = T;//const char*;
    const char* value{};

    Promise() = default;
    std::suspend_always initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void unhandled_exception() { std::rethrow_exception(std::current_exception()); }

    std::suspend_always yield_value(const char* value) {
        this->value = std::move(value);
        return {};
    }

    // void return_value(const char* value) {
    //     this->value = std::move(value);
    // }

    void return_void() {
        this->value = nullptr;
    }

    Future get_return_object();
};

class Future
{
public:
    using promise_type = Promise<const char*>;

    explicit Future(std::coroutine_handle<promise_type> handle)
        : handle (handle) 
    {}

    ~Future() {
        if (handle) { handle.destroy(); }
    }
    
    promise_type::value_type next() {
        if (handle) {
            handle.resume();
            return handle.promise().value;
        }
        else {
            return {};
        }
    }

private:
    std::coroutine_handle<promise_type> handle{};    
};

template <typename T>
Future Promise<T>::get_return_object()
{
    return Future{ std::coroutine_handle<Promise<T>>::from_promise(*this) };
}


// co-routine
Future Generator()
{
    co_yield "Hello ";
    co_yield "world";
    co_yield "!";
    //co_return;
}

int main()
{
    // auto generator = Generator();
    // std::cout << generator.next();
    // std::cout << generator.next();
    // std::cout << generator.next();
    // std::cout << std::endl;
	
	auto generator = Generator();
	while (const char* item = generator.next()) 
    {
		std::cout << item;
	}
	std::cout << std::endl;

    return 0;
}