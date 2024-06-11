#include <iostream>

#include <sharechain/share.hpp>
#include <core/chain.hpp>

struct FakeShareA : c2pool::chain::BaseShare<10>
{
    int m_data1;

    FakeShareA() {}
    FakeShareA(int data1) : m_data1{data1} {}
};

struct FakeShareB : c2pool::chain::BaseShare<20>
{
    double m_data2;

    FakeShareB() {}
    FakeShareB(double data2) : m_data2{data2} {}
};

using ShareType = c2pool::chain::ShareVariants<FakeShareA, FakeShareB>;

struct FakeRule : c2pool::core::ChainRule<ShareType>
{

};

struct FakeChain : c2pool::core::Chain<FakeRule>
{

};

int main()
{
    FakeChain chain;

    chain.add(FakeShareA{100});
    chain.add(FakeShareB(200.222));
}