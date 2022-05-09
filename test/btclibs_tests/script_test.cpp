#include <gtest/gtest.h>
#include <btclibs/script/script.h>
#include <btclibs/core_io.h>
#include <btclibs/util/strencodings.h>

#include <iostream>

TEST(script, runtime_errors)
{
    const std::vector<std::pair<std::string,std::string>> IN_OUT{
            // {IN: script string , OUT: hex string }
            {"", ""},
            {"0", "00"},
            {"1", "51"},
            {"2", "52"},
            {"3", "53"},
            {"4", "54"},
            {"5", "55"},
            {"6", "56"},
            {"7", "57"},
            {"8", "58"},
            {"9", "59"},
            {"10", "5a"},
            {"11", "5b"},
            {"12", "5c"},
            {"13", "5d"},
            {"14", "5e"},
            {"15", "5f"},
            {"16", "60"},
            {"17", "0111"},
            {"-9", "0189"},
            {"0x17", "17"},
            {"'17'", "023137"},
            {"ELSE", "67"},
            {"NOP10", "b9"},
    };

    std::string all_in;
    std::string all_out;
    for (const auto& [in, out] : IN_OUT)
    {
        ASSERT_EQ(HexStr(ParseScript(in)), out);

        all_in += " " + in + " ";
        all_out += out;
    }
    ASSERT_EQ(HexStr(ParseScript(all_in)), all_out);

    ASSERT_THROW(ParseScript("11111111111111111111"), std::runtime_error);
    ASSERT_THROW(ParseScript("11111111111"), std::runtime_error);
    ASSERT_THROW(ParseScript("OP_CHECKSIGADD"), std::runtime_error);
}

TEST(script, parse)
{
    CScript sc;
//    sc << ;
//    std::cout << ParseHex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac") << std::endl;
    sc << ParseHex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac");

    std::cout << HexStr(sc) << std::endl;
    std::cout << sc.IsPayToScriptHash() << std::endl;

//    auto s = ParseScript(HexStr("76 a9 14 89 ab cd ef ab ba ab ba ab ba ab ba ab ba ab ba ab ba ab ba 88 ac"));
//    std::cout << "s: " << s << std::endl;
//ToByteVector()
//    ParseScript(s);
}