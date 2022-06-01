#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>

#include <libdevcore/filesystem.h>
#include <libdevcore/addr_store.h>

using namespace std;

TEST(DevcoreTest, FilesystemTest)
{
    std::string expectedOutput = "1";
    auto path = c2pool::filesystem::findFile("testing");
    cout << path << endl;
    std::fstream t = c2pool::filesystem::getFile("testing");
    t << expectedOutput;
    t.close();
    t = c2pool::filesystem::getFile("testing", ios_base::in);
    std::string genfile;
    t >> genfile;
    EXPECT_EQ(expectedOutput, genfile);
}