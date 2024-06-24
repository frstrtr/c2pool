#include <iostream>

#include <core/pack.hpp>
#include <sharechain/share.hpp>
#include <sharechain/sharechain.hpp>

template <int64_t Version>
struct BaseFakeShare : c2pool::chain::BaseShare<int, Version>
{
    BaseFakeShare() { }
    BaseFakeShare(int hash, int prev_hash) : c2pool::chain::BaseShare<int, Version>(hash, prev_hash) { }
    
    SERIALIZE_METHODS(BaseFakeShare<Version>) { READWRITE(obj.m_hash, obj.m_prev_hash); }
};

struct FakeShareA : BaseFakeShare<10>
{
    int m_data1;

    FakeShareA() {}
    FakeShareA(int hash, int prev_hash, int data1) : BaseFakeShare<10>(hash, prev_hash), m_data1{data1} {}
    
    SERIALIZE_METHODS(FakeShareA) { READWRITE(AsBase<BaseFakeShare<10>>(obj), obj.m_data1); }
};

struct FakeShareB : BaseFakeShare<20>
{
    double m_data2;

    FakeShareB() {}
    FakeShareB(int hash, int prev_hash, double data2) : BaseFakeShare<20>(hash, prev_hash), m_data2{data2} {}

    SERIALIZE_METHODS(FakeShareB) { READWRITE(AsBase<BaseFakeShare<20>>(obj)/*, obj.m_data2*/); }
};

using ShareType = c2pool::chain::ShareVariants<FakeShareA, FakeShareB>;

class FakeIndex : public c2pool::chain::ShareIndex<int, ShareType, std::hash<int>, FakeIndex>
{
private:
    using base_index = c2pool::chain::ShareIndex<int, ShareType, std::hash<int>, FakeIndex>;
public:

    int data1{0};
    double data2{0};

    FakeIndex() : base_index() {}
    template <typename ShareT> FakeIndex(ShareT* share) : base_index(share)
    {
        if constexpr(ShareT::version == 10)
            data1 = share->m_data1;
        if constexpr(ShareT::version == 20)
            data2 = share->m_data2;
    }

protected:
    void add(FakeIndex* index) override
    {
        data1 += index->data1;
        data2 += index->data2;
    }

    void sub(FakeIndex* index) override
    {
        data1 -= index->data1;
        data2 -= index->data2;
    }
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

void debug_print(FakeChain& chain, FakeIndex::hash_t hash)
{
    std::cout << "====================" << std::endl;
    std::cout << "Print for hash [" << hash << "]" << std::endl;
    chain.debug();
    auto& [index, data] = chain.get(std::move(hash));
    std::cout << "data1 = " << index->data1 << "; data2 = " << index->data2 << "; height = " << index->height << std::endl;
    std::cout << "====================" << std::endl;
}

int main()
{
    FakeChain chain;
    
    // chain.add(new FakeShareA(11, 10, 100));
    // chain.add(new FakeShareB(12, 11, 200.222));

    // auto share = chain.get_share(11);
    // share.invoke(test_f);
    // debug_print(chain, 12);

    // chain.add(new FakeShareA(14, 13, 50));
    // chain.add(new FakeShareA(15, 14, 20));
    // debug_print(chain, 15);
    // chain.debug();

    // chain.add(new FakeShareB(13, 12, 10));
    // debug_print(chain, 15);

    // chain.debug();

    chain.add(new FakeShareA(11, 10, 100));
    debug_print(chain, 11);
    chain.add(new FakeShareB(13, 12, 10));
    debug_print(chain, 13);
    chain.add(new FakeShareB(12, 11, 200.222));
    debug_print(chain, 13);
    chain.add(new FakeShareB(14, 13, 10));
    debug_print(chain, 14);
    chain.add(new FakeShareA(10, 9, 1000.20));
    debug_print(chain, 14);


    auto interval = chain.get_interval(14, 11); // [14, 13, 12]
    std::cout << "interval: data1 = " << interval.data1 << "; data2 = " << interval.data2 << "; height = " << interval.height << std::endl;
    debug_print(chain, 14);

    PackStream stream;
    chain.get_share(11).pack(stream);
    auto share = ShareType::load(FakeShareA::version, stream);
    share.call(test_f);
}