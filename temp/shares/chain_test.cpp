#include <iostream>

#include <sharechain/share.hpp>
#include <sharechain/sharechain.hpp>

template <int64_t Version>
struct BaseFakeShare : c2pool::chain::BaseShare<Version>
{
    int m_hash;
    int m_prev_hash;

    BaseFakeShare() { }
    BaseFakeShare(int hash, int prev_hash) : m_hash(hash), m_prev_hash(prev_hash) { }
};

struct FakeShareA : BaseFakeShare<10>
{
    int m_data1;

    FakeShareA() {}
    FakeShareA(int hash, int prev_hash, int data1) : BaseFakeShare<10>(hash, prev_hash), m_data1{data1} {}
};

struct FakeShareB : BaseFakeShare<20>
{
    double m_data2;

    FakeShareB() {}
    FakeShareB(int hash, int prev_hash, double data2) : BaseFakeShare<20>(hash, prev_hash), m_data2{data2} {}
};

using ShareType = c2pool::chain::ShareVariants<FakeShareA, FakeShareB>;

class FakeIndex : public c2pool::chain::ShareIndex<int, ShareType, std::hash<int>>
{

};

struct FakeChain : c2pool::chain::ShareChain<FakeIndex>
{

};

template <typename share_t>
void test_f(share_t* share)
{
    if (!share)
        return;

    std::cout << "Share (" << share->m_prev_hash << " -> " << share->m_hash << "): ";

    if constexpr (share_t::version == 10)
        std::cout << share->m_data1 << std::endl;
    if constexpr (share_t::check_version(20))
        std::cout << share->m_data2 << std::endl;
}

int main()
{
    FakeChain chain;
    
    chain.add(new FakeShareA(11, 10, 100));
    chain.add(new FakeShareB(12, 11, 200.222));

    auto share = chain.get_share(11);
    share.INVOKE(test_f);
}