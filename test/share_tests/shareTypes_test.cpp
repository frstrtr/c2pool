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
    std::shared_ptr<SmallBlockHeaderType> min_header = = std::make_shared<SmallBlockHeaderType>(1, "02", 2, 3, 4);

    std::shared_ptr<ShareData> share_data = std::make_shared<ShareData>("01", "a", 2, "03", 4, 5, 253, 6);

    std::vector<uint256> branch_txidml {"01"};
    std::shared_ptr<MerkleLink> txid_merkle_link = std::make_shared<MerkleLink>(branch_txidml, 1)
    std::shared_ptr<SegwitData> segwit_data = std::make_shared<SegwitData>(txid_merkle_link, "02");
    
    std::vector<uint256> new_transaction_hashes{"01"};
    std::vector<TransactionHashRef> transaction_hash_refs;
    TransactionHashRef thr(0, 1);
    transaction_hash_reft.push_back(thr);
    std::shared_ptr<ShareInfoType>
        share_info = std::make_shared<ShareInfoType>(share_data,
                                                     segwit_data,
                                                     new_transaction_hashes,
                                                     transaction_hash_refs,
                                                     "022", 22, 33, 44, 55);


    std::vector<uint256> branch_rml {"01"};
    std::shared_ptr<MerkleLink> ref_merkle_link = std::make_shared<MerkleLink>(branch_rml, 111);
    
    std::shared_ptr<HashLinkType> hash_link = std::make_shared<HashLInkType>("a", "b", 2);

    std::vector<uint256> branch_ml {"01"};
    std::shared_ptr<MerkleLink> merkle_link = std::make_shared<MerkleLink>(branch_ml, 222);

    c2pool::shares::ShareType shareType1(min_header,
                                         share_info,
                                         ref_merkle_link,
                                         64,
                                         hash_link,
                                         merkle_link);
    c2pool::shares::ShareType shareType2();
    std::stringstream ss;
    
    ss << 1 << "02" << 2 << 3 << 4 //SmallBlockHeaderType
       << "01" << "a" << 2 << "03" << 4 << 5 << 253 << 6 //ShareData
       << 1 /*length vector in txid_merkle_link*/ << "01" << 1 << "02" //MerkleLink
       << 1 /*length vector new_transaction_hashes*/ << "01" //new_transaction_hashes
       << 1 /*length vector transaction_hash_refs*/ << 0 << 1 //transaction_hash_refs
       << "022" << 22 << 33 << 44 << 55;
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