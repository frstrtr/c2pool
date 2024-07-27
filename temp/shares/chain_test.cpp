#include <iostream>

#include <core/pack.hpp>
#include <sharechain/share.hpp>
#include <sharechain/sharechain.hpp>

template <int64_t Version>
struct BaseFakeShare : chain::BaseShare<int, Version>
{
    BaseFakeShare() { }
    BaseFakeShare(int hash, int prev_hash) : chain::BaseShare<int, Version>(hash, prev_hash) { }
};

struct FakeShareA : BaseFakeShare<10>
{
    int m_data1;

    FakeShareA() {}
    FakeShareA(int hash, int prev_hash, int data1) : BaseFakeShare<10>(hash, prev_hash), m_data1{data1} {}
};

struct FakeShareB : BaseFakeShare<20>
{
    std::string m_data2;

    FakeShareB() {}
    FakeShareB(int hash, int prev_hash, std::string data2) : BaseFakeShare<20>(hash, prev_hash), m_data2{data2} {}
};

struct FakeShareFormatter
{
    SHARE_FORMATTER()
    {
        READWRITE(obj->m_hash, obj->m_prev_hash);

        if constexpr (version == 10)
            READWRITE(obj->m_data1);
        
        if constexpr (version == 20)
            READWRITE(obj->m_data2);
    }
};

using ShareType = chain::ShareVariants<FakeShareFormatter, FakeShareA, FakeShareB>;

class FakeIndex : public chain::ShareIndex<int, ShareType, std::hash<int>, FakeIndex>
{
private:
    using base_index = chain::ShareIndex<int, ShareType, std::hash<int>, FakeIndex>;
public:

    int data1{0};

    FakeIndex() : base_index() {}
    template <typename ShareT> FakeIndex(ShareT* share) : base_index(share)
    {
        if constexpr(ShareT::version == 10)
            data1 = share->m_data1;
    }

protected:
    void add(FakeIndex* index) override
    {
        data1 += index->data1;
    }

    void sub(FakeIndex* index) override
    {
        data1 -= index->data1;
    }
};

struct FakeChain : chain::ShareChain<FakeIndex>
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

template <typename share_t>
void test_f2(share_t* share, int i, float f)
{
    std::cout << i << " " << f << std::endl;
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
    std::cout << "data1 = " << index->data1 << "; height = " << index->height << std::endl;
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
    chain.add(new FakeShareB(13, 12, "10"));
    debug_print(chain, 13);
    chain.add(new FakeShareB(12, 11, "200.222"));
    debug_print(chain, 13);
    chain.add(new FakeShareB(14, 13, "30"));
    debug_print(chain, 14);
    chain.add(new FakeShareA(10, 9, 1000.20));
    debug_print(chain, 14);


    auto interval = chain.get_interval(14, 11); // [14, 13, 12]
    std::cout << "interval: data1 = " << interval.data1 << "; height = " << interval.height << std::endl;
    debug_print(chain, 14);

    PackStream stream;
    chain.get_share(11).pack(stream);
    auto share = ShareType::load(FakeShareA::version, stream);
    auto share_copy = share;

    share.CALL(test_f2, 10, 2.2);

    share_copy.ACTION(
        {
            if constexpr (share_t::version == 10)
            {
                std::cout << "! -> " << obj->m_data1 << std::endl;
                obj->m_data1 += 322;
            }
        }
    );

    share.USE(test_f);

    std::cout << share.hash() << " <--- " << share.prev_hash() << std::endl;

    
}