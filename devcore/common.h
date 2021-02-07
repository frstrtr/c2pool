#pragma once

#include <ctime>
#include <memory>

namespace c2pool::dev
{
    //TODO: create timestamp class
    int timestamp();

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