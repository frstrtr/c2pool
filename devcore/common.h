#pragma once
#include <ctime>
#include <memory>

namespace c2pool::dev
{
    //STR
    //from [exclude]
    void substr(char *dest, char *source, int from, unsigned int length);

    char *from_bytes_to_strChar(char *source);

    //char и unsigned char будут так же верно сравниваться.
    //true - equaled
    bool compare_str(const void *first_str, const void *second_str, unsigned int length);
    //====

    //TODO: create timestamp class
    int timestamp()
    {
        return std::time(nullptr);
    }
    
    template <typename Derived, typename Base, typename Del>
    std::unique_ptr<Derived, Del>
    static_unique_ptr_cast(std::unique_ptr<Base, Del> &&p)
    {
        auto d = static_cast<Derived *>(p.release());
        return std::unique_ptr<Derived, Del>(d, std::move(p.get_deleter()));
    }

    class ExitSignalHandler
    {
    public:
        static void handler(int) { work_status = false; }
        bool working() const { return work_status; }

    private:
        static bool work_status; //true = working, false = exit.
    };

    //errors in main
    enum C2PoolErrors
    {
        success = 0
    };
} // namespace c2pool::dev