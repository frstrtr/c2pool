#include <iostream>
#include <tuple>
// legacy
#include <btclibs/uint256.h>
#include <btclibs/hash.h>

// actual
// #include <core/uint256.h>


using result_type = std::tuple<std::string, std::string>;

template <typename HasherT, typename UIntT>
result_type test(const std::string& name, UIntT& num)
{
    std::cout << "=====" << name << "=====" << std::endl;
    std::cout << "num = " << num.GetHex() << std::endl;
    auto temp = (HasherT{} << num);
    auto result = std::make_tuple(temp.GetHash().GetHex(), temp.GetSHA256().GetHex());
    std::cout << "result:\n\tHash = " << std::get<0>(result) << "\n\tSHA256 = " << std::get<1>(result) << std::endl;
    std::cout << "===================" << std::endl;
    return result;
}

int main()
{
    std::string data = "123";
    // uint256 n1{data};
    // std::string hash1 = test("first", n1);

    legacy::uint256 n2 = legacy::uint256S(data);
    auto hash2 = test<legacy::HashWriter>("second", n2);

    // std::cout << "Equal nums?: " << ((n1.GetHex() == n2.GetHex()) ? "true" : "false") << std::endl;
    // std::cout << "Equal hashes?: " << ((hash1 == hash2) ? "true" : "false") << std::endl;
}