#include <iostream>
#include <tuple>
// legacy
#include <btclibs/util/strencodings.h>
#include <btclibs/uint256.h>
#include <btclibs/hash.h>
#undef SERIALIZE_METHODS
#undef READWRITE

// actual
#include <core/uint256.hpp>
#include <core/hash.hpp>


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

uint256 hash256(std::string data, bool reverse)
{
    uint256 result;

    std::vector<unsigned char> out1;
    out1.resize(CSHA256::OUTPUT_SIZE);

    std::vector<unsigned char> out2;
    out2.resize(CSHA256::OUTPUT_SIZE);

    // CSHA256().Write((unsigned char *)&data[0], data.length()).Finalize(&out1[0]);
    // CSHA256().Write((unsigned char *)&out1[0], out1.size()).Finalize(&out2[0]);

    CSHA256().Write((unsigned char *)&data[0], 32).Finalize(&out1[0]);
    CSHA256().Write((unsigned char *)&out1[0], 32).Finalize(&out2[0]);

    if (reverse)
        std::reverse(out2.begin(), out2.end());
    result.SetHex(HexStr(out2));

    return result;
}

// int main()
// {
//     std::string data = "123456789";
//     uint256 n1(data);
//     auto hash1 = test<HashWriter>("first", n1);

//     legacy::uint256 n2 = legacy::uint256S(data);
//     auto hash2 = test<legacy::HashWriter>("second", n2);

//     std::cout << "Equal nums?: " << ((n1.GetHex() == n2.GetHex()) ? "true" : "false") << std::endl;
//     std::cout << "Equal hashes?: " << ((hash1 == hash2) ? "true" : "false") << std::endl;
// }

// int main()
// {
//     // std::vector<uint8_t> data = {'a', 'b', 'c'};
//     // uint32_t data = 0x616263;
//     legacy::uint256 data;
//     data.SetNull();
//     data.SetHex("ff");
//     std::cout << data.GetHex() << std::endl;

//     // auto hash1 = (HashWriter{} << data);
//     auto hash2 = (legacy::HashWriter{} << data);

//     // std::cout << "new:\t" << hash1.GetHash().GetHex() << "\n\t" << hash1.GetSHA256().GetHex() << std::endl;
//     std::cout << "legacy:\t" << hash2.GetHash().GetHex() << "\n\t" << hash2.GetSHA256().GetHex() << std::endl;

//     std::cout << "legacy::Hash: " << legacy::Hash(data).GetHex() << std::endl;
//     std::cout << "c2pool hash256: " << hash256(data.GetHex(), true) << std::endl;
//     std::cout << "double SHA256Uint256: " << legacy::SHA256Uint256(legacy::SHA256Uint256(legacy::uint256S("ff"))).GetHex() << std::endl;
// }

// int main()
// {
//     std::vector<unsigned char> in = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x61, 0x62, 0x63};
//     std::vector<unsigned char> hash;
//     hash.resize(32);
//     CSHA256(CSHA256{}).Write((unsigned char*)in.data(), 32).Finalize(&hash[0]);
//     std::cout << HexStr(hash) << std::endl;


// }

// int main()
// {
//     legacy::uint256 comp;
//     comp.SetHex("e51600d48d2f72eb428e78733e01fbd6081b349528335bf21269362edfae185d");
//     std::vector<unsigned char> str {0xaa};
//     Span<unsigned char> sp(str);
//     // std::cout << legacy::Hash("abc").GetHex() << std::endl;
//     std::cout << (comp == legacy::Hash(sp)) << std::endl;
// }

int main()
{
    std::vector<unsigned char> str {0xaa};
    std::span<unsigned char> sp(str);
    std::cout << Hash(sp) << std::endl;
}