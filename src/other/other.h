#ifndef CPOOL_OTHER_H
#define CPOOL_OTHER_H

#include <vector>
#include <map>
#include <memory>
#include <iterator>
#include <string>

namespace c2pool::random
{
    ///[min, max)
    int RandomInt(int min, int max);

    ///[min, max]
    float RandomFloat(float min, float max);

    template <typename T>
    T RandomChoice(std::vector<T> &list);

    template <typename K, typename V>
    V RandomChoice(std::map<K, V> m)
    { //TODO: THIS WANNA TEST
        int pos = RandomInt(0, m.size());
        std::iterator item = m.cbegin();
        return std::advance(item, pos);
    }

    ///l = 1.0/<среднее желаемое число>
    float Expovariate(float l);

    unsigned long long RandomNonce();
} // namespace c2pool::random

namespace c2pool::time
{
    int timestamp();
}

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

    //from [exclude]
    void substr(char *dest, char *source, int from, unsigned int length);

    char *from_bytes_to_strChar(char *source);

    //char и unsigned char будут так же верно сравниваться.
    //true - equaled
    bool compare_str(const void* first_str, const void* second_str, unsigned int length);

    //TODO: add str_to_int for char*
    int str_to_int(std::string s);
} // namespace c2pool::str

#endif //CPOOL_OTHER_H