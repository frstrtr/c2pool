#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <shareTypes.h>
#include <sstream>

//TODO: create CMakeList.txt
TEST(Shares, HashLinkTypeTest)
{
    c2pool::shares::HashLinkType hashLinkType1("1", "2");
    c2pool::shares::HashLinkType hashLinkType2;
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> hashLinkType2;
    ASSERT_EQ(hashLinkType1, hashLinkType2);
    c2pool::shares::HashLinkType hashLinkType3;
    std::stringstream ss2;
    ss2 << hashLinkType1;
    ss2 >> hashLinkType3;
    ASSERT_EQ(hashLinkType1, hashLinkType3);
}

TEST(Shares, MerkleLink)
{
    c2pool::shares::MerkleLink merkleLink1();
    c2pool::shares::MerkleLink merkleLink2();
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> merkleLink2;
    ASSERT_EQ(merkleLink1, merkleLink2);
    c2pool::shares::MerkleLink merkleLink3;
    std::stringstream ss2;
    ss2 << merkleLink1;
    ss2 >> merkleLink3;
    ASSERT_EQ(hashLinkType1, hashLinkType3);
}

TEST(Shares, SmallBlockHeaderType)
{
    c2pool::shares::SmallBlockHeaderType smallBlockHeaderType1();
    c2pool::shares::SmallBlockHeaderType smallBlockHeaderType2();
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> smallBlockHeaderType2;
    ASSERT_EQ(smallBlockHeaderType1, smallBlockHeaderType2);
    c2pool::shares::SmallBlockHeaderType smallBlockHeaderType3;
    std::stringstream ss2;
    ss2 << smallBlockHeaderType1;
    ss2 >> smallBlockHeaderType3;
    ASSERT_EQ(smallBlockHeaderType1, smallBlockHeaderType3);
}

TEST(Shares, ShareData)
{
    c2pool::shares::ShareData shareData1();
    c2pool::shares::ShareData shareData2();
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> shareData2;
    ASSERT_EQ(shareData1, shareData2);
    c2pool::shares::ShareData shareData3;
    std::stringstream ss2;
    ss2 << shareData1;
    ss2 >> shareData3;
    ASSERT_EQ(shareData1, shareData3);
}

TEST(Shares, SegwitData)
{
    c2pool::shares::SegwitData segwitData1();
    c2pool::shares::SegwitData segwitData2();
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> segwitData2;
    ASSERT_EQ(segwitData1, segwitData2);
    c2pool::shares::SegwitData segwitData3;
    std::stringstream ss2;
    ss2 << segwitData1;
    ss2 >> segwitData3;
    ASSERT_EQ(segwitData1, segwitData3);
}

TEST(Shares, TransactionHashRef)
{
    c2pool::shares::TransactionHashRef transactionHashRef1();
    c2pool::shares::TransactionHashRef transactionHashRef2();
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> transactionHashRef2;
    ASSERT_EQ(transactionHashRef1, transactionHashRef2);
    c2pool::shares::TransactionHashRef transactionHashRef3;
    std::stringstream ss2;
    ss2 << transactionHashRef1;
    ss2 >> transactionHashRef3;
    ASSERT_EQ(transactionHashRef1, transactionHashRef3);
}

TEST(Shares, ShareInfoType)
{
    c2pool::shares::ShareInfoType shareInfoType1();
    c2pool::shares::ShareInfoType shareInfoType2();
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> shareInfoType2;
    ASSERT_EQ(shareInfoType1, shareInfoType2);
    c2pool::shares::ShareInfoType shareInfoType3;
    std::stringstream ss2;
    ss2 << shareInfoType1;
    ss2 >> shareInfoType3;
    ASSERT_EQ(shareInfoType1, shareInfoType3);
}

TEST(Shares, ShareType)
{
    c2pool::shares::ShareType shareType1();
    c2pool::shares::ShareType shareType2();
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> shareType2;
    ASSERT_EQ(shareType1, shareType2);
    c2pool::shares::ShareType shareType3;
    std::stringstream ss2;
    ss2 << shareType1;
    ss2 >> shareType3;
    ASSERT_EQ(shareType1, shareType3);
}

TEST(Shares, RefType)
{
    c2pool::shares::RefType refType1();
    c2pool::shares::RefType refType2();
    std::stringstream ss;
    ss << "1"
       << " "
       << "2";
    ss >> refType2;
    ASSERT_EQ(refType1, refType2);
    c2pool::shares::RefType refType3;
    std::stringstream ss2;
    ss2 << refType1;
    ss2 >> refType3;
    ASSERT_EQ(refType1, refType3);
}