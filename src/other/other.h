#ifndef CPOOL_OTHER_H
#define CPOOL_OTHER_H

#include <vector>
#include <memory>

namespace c2pool::random
{
    ///[min, max)
    int RandomInt(int min, int max);

    ///[min, max]
    float RandomFloat(float min, float max);

    template <typename T>
    T RandomChoice(std::vector<T> list);

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l);
} // namespace c2pool::random

namespace c2pool::time
{
    int timestamp();
}

namespace c2pool::str
{
    void substr(char *dest, char *source, int from, int length);
} // namespace c2pool::str

namespace c2pool::smart_ptr
{
    template <typename Derived, typename Base, typename Del>
    std::unique_ptr<Derived, Del>
    static_unique_ptr_cast(std::unique_ptr<Base, Del> &&p)
    {
        auto d = static_cast<Derived *>(p.release());
        return std::unique_ptr<Derived, Del>(d, std::move(p.get_deleter()));
    }
} // namespace c2pool::smart_ptr

namespace c2pool::str
{
    void substr(char *dest, char *source, int from, int length);
} // namespace c2pool::str

#endif //CPOOL_OTHER_H