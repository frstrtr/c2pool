#include "data.h"

#include <btclibs/uint256.h>
#include <btclibs/arith_uint256.h>
#include <univalue.h>
#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/cxx17/reduce.hpp>

#include <sstream>
#include <algorithm>

#include "transaction.h"


namespace coind::data
{
    [[maybe_unused]]bool is_segwit_tx(UniValue tx)
    {
        if (tx.exists("marker") && tx.exists("flag"))
        {
            return tx["marker"].get_int() == 0 && tx["flag"].get_int() >= 1;
        }
        return false;
    }

    bool is_segwit_tx(std::shared_ptr<TransactionType> tx)
    {
        if (tx)
        {
            return tx->wdata.has_value() && tx->wdata->marker == 0 && tx->wdata->flag >= 1;
        }
        return false;
    }

    uint256 target_to_average_attempts(uint256 target)
    {
        //TODO: return coind::data::python::PyBitcoindData::target_to_average_attempts(target);
    }

    uint256 average_attempts_to_target(uint256 average_attempts)
    {
        //TODO: return coind::data::python::PyBitcoindData::average_attempts_to_target(average_attempts);
    }

    double target_to_difficulty(uint256 target)
    {
//1
//        auto bits = UintToArith256(target).GetCompact();
//        int nShift = (bits >> 24) & 0xff;
//        double dDiff =
//                (double)0x0000ffff / (double)(bits & 0x00ffffff);
//
//        while (nShift < 29)
//        {
//            dDiff *= 256.0;
//            nShift++;
//        }
//        while (nShift > 29)
//        {
//            dDiff /= 256.0;
//            nShift--;
//        }
//
//        return dDiff;

// 2
//        auto targ = UintToArith256(target);
//        assert(!target.IsNull());
//
//        auto ss = UintToArith256(uint256S("ffff0000000000000000000000000000000000000000000000000001"));
//        auto rr = (ss)/(targ+1);
////        return rr.getdouble();
// 3
//        uint288 targ;
//        targ.SetHex(target.GetHex());
//
//        auto v = UintToArith288(targ);
//        std::cout << "v: " << v.GetHex() << std::endl;
//        assert(!target.IsNull());
//
//        uint288 u_s;
//        u_s.SetHex("1000000000000000000000000000000000000000000000000");
//
//        auto s = UintToArith288(u_s);
//        s *= 0xffff0000;
//        s += 1;
//
//        auto r = s/(v+1);
//        return r.getdouble();
//4
//        uint288 targ;
//        targ.SetHex(target.GetHex());
//        auto bits = UintToArith288(targ).GetCompact();
//        int nShift = (bits >> 24) & 0xff;
//        double dDiff =
//                (double)0x0000ffff / (double)(bits & 0x00ffffff);
//
//        while (nShift < 29)
//        {
//            dDiff *= 256.0;
//            nShift++;
//        }
//        while (nShift > 29)
//        {
//            dDiff /= 256.0;
//            nShift--;
//        }
//
//        return dDiff;
//5
        uint288 targ;
        targ.SetHex(target.GetHex());

        auto v = UintToArith288(targ);
        std::cout << "v: " << v.GetHex() << std::endl;
        assert(!target.IsNull());

        uint288 u_s;
        u_s.SetHex("1000000000000000000000000000000000000000000000000");

        auto s = UintToArith288(u_s);
        s *= 0xffff0000;
        s += 1;

        auto r = s/(v+1);
        std::cout << "Not a Double: " << r.GetHex() << std::endl;
        return r.getdouble();
    }

    uint256 difficulty_to_target(uint256 difficulty)
    {
        uint288 targ;
        targ.SetHex(difficulty.GetHex());

        auto v = UintToArith288(targ);
        std::cout << "v: " << v.GetHex() << std::endl;
        if (targ.IsNull() || ((v-1) < 0))
            return uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        uint288 u_s;
        u_s.SetHex("1000000000000000000000000000000000000000000000000");

        auto s = UintToArith288(u_s);
        s *= 0xffff0000;
        s += 1;

        auto r = s/(v)-1;

        arith_uint256 r_round;
        r_round.SetCompact(UintToArith256(uint256S(r.GetHex())).GetCompact() + 0.5);
        r.SetHex(ArithToUint256(r_round).GetHex());

        std::cout << "Not a Double: " << r.GetHex() << std::endl;
        return uint256S(r.GetHex()) ;
    }

	uint256 get_txid(shared_ptr<coind::data::TransactionType> tx)
	{
		coind::data::stream::TxIDType_stream txid_stream(tx->version, tx->tx_ins, tx->tx_outs, tx->lock_time);
		PackStream stream;
		stream << txid_stream;
		return hash256(stream);
	}

	uint256 get_wtxid(shared_ptr<coind::data::TransactionType> tx, uint256 txid, uint256 txhash)
	{
		bool has_witness = false;
		if (is_segwit_tx(tx))
		{
            assert(tx->tx_ins.size() == tx->wdata->witness.size());
            for (auto w : tx->wdata->witness)
            {
                if (w.size() > 0)
                {
                    has_witness = true;
                    break;
                }
            }
		}

		PackStream packed_tx;
		if (has_witness)
		{
			if (txhash.IsNull())
				return txhash;

			coind::data::stream::TransactionType_stream _tx(tx);
			packed_tx << _tx;
		} else
		{
			if (txid.IsNull())
				return txid;

			coind::data::stream::TxIDType_stream _tx(tx->version,tx->tx_ins, tx->tx_outs, tx->lock_time);
			packed_tx << _tx;
		}
		return hash256(packed_tx);
	}

    uint256 hash256(std::string data, bool reverse)
    {
        uint256 result;

        vector<unsigned char> out1;
        out1.resize(CSHA256::OUTPUT_SIZE);

        vector<unsigned char> out2;
        out2.resize(CSHA256::OUTPUT_SIZE);

        CSHA256().Write((unsigned char *)&data[0], data.length()).Finalize(&out1[0]);
        CSHA256().Write((unsigned char *)&out1[0], out1.size()).Finalize(&out2[0]);

        auto _hash = HexStr(out2);
        result.SetHex(_hash);
		if (reverse)
        	std::reverse(result.begin(), result.end());

        return result;
    }

    uint256 hash256(PackStream stream, bool reverse)
    {
        auto _bytes = stream.bytes();
        string in(reinterpret_cast<char const *>(_bytes), stream.size());
        return hash256(in, reverse);
    }

    uint256 hash256(uint256 data, bool reverse)
    {
        string in = data.GetHex();
        return hash256(in, reverse);
    }

    uint160 hash160(string data, bool reverse)
    {
        uint160 result;

        vector<unsigned char> out1;
        out1.resize(CSHA256::OUTPUT_SIZE);

        vector<unsigned char> out2;
        out2.resize(CRIPEMD160::OUTPUT_SIZE);

        CSHA256().Write((unsigned char *)&data[0], data.length()).Finalize(&out1[0]);
        CRIPEMD160().Write((unsigned char *)&out1[0], out1.size()).Finalize(&out2[0]);
        result.SetHex(HexStr(out2));

		if (reverse)
			std::reverse(result.begin(), result.end());

        return result;
    }

    uint160 hash160(PackStream stream, bool reverse)
    {
        auto _bytes = stream.bytes();
        string in(reinterpret_cast<char const *>(_bytes), stream.size());
        return hash160(in, reverse);
    }

    uint160 hash160(uint160 data, bool reverse)
    {
        string in = data.GetHex();
        return hash160(in, reverse);
    }

    uint256 hash256_from_hash_link(uint32_t init[8], vector<unsigned char> data, vector<unsigned char> buf, uint64_t length)
    {
        uint256 result;

        if (!buf.size())
            buf.push_back('\0');

        vector<unsigned char> out1;
        out1.resize(CSHA256::OUTPUT_SIZE);

        vector<unsigned char> out2;
        out2.resize(CSHA256::OUTPUT_SIZE);

        CSHA256(init, buf, length).Write((unsigned char *)&data[0], data.size()).Finalize(&out1[0]);
        CSHA256().Write((unsigned char *)&out1[0], out1.size()).Finalize(&out2[0]);

        result.SetHex(HexStr(out2));
        reverse(result.begin(), result.end());

        return result;
    }

    PackStream pubkey_hash_to_script2(uint160 pubkey_hash)
    {
        auto packed_pubkey_hash = IntType(160)(pubkey_hash);

        PackStream result;
        result << vector<unsigned char>({0x76, 0xa9, 0x14}) << packed_pubkey_hash << vector<unsigned char>({0x88, 0xac});

        return result;
    }
}

//MerkleTree
namespace coind::data
{
    MerkleLink calculate_merkle_link(std::vector<uint256> hashes, int32_t index)
	{
		struct _side_data{
			bool side;
			uint256 hash;

			_side_data() = default;
			_side_data(bool _side, uint256 _hash)
			{
				hash = _hash;
			}
		};

		struct _hash_list_data{
			uint256 value;
			bool f;
			std::vector<_side_data> l;

			_hash_list_data() = default;
			_hash_list_data(uint256 _value, bool _f, std::vector<_side_data> _l) {
				value = _value;
				f = _f;
				l = _l;
			}
		};

		std::vector<_hash_list_data> hash_list;
		for (int i = 0; i < hashes.size(); i++)
		{
			hash_list.emplace_back(hashes[i], i == index, std::vector<_side_data>{});
		}

		while (hash_list.size() > 1)
		{
            //TODO: Optimize
            std::vector<_hash_list_data> new_hash_list;

            std::vector<_hash_list_data> evens = math::every_nth_element(hash_list.begin(), hash_list.end(), 2);

            std::vector<_hash_list_data> odds = math::every_nth_element(hash_list.begin()+1, hash_list.end(), 2);
            odds.push_back(evens.back());

            _hash_list_data left, right;
            BOOST_FOREACH(boost::tie(left, right), boost::combine(evens, odds))
                        {
                            merkle_record_type record(left.value, right.value);
                            PackStream _stream;
                            _stream << record;
                            uint256 _hash = hash256(_stream);

                            std::vector<_side_data> _l = left.f ? left.l : right.l;
                            _l.push_back(left.f ? _side_data(1, right.value) : _side_data(0, left.value));

                            new_hash_list.emplace_back(_hash, left.f || right.f, _l);
                        }
            hash_list = new_hash_list;
		}

        std::vector<uint256> res_branch;
        for (auto v: hash_list[0].l){
            res_branch.push_back(v.hash);
        }

        return MerkleLink(res_branch, index);
	}

    uint256 check_merkle_link(uint256 tip_hash, coind::data::MerkleLink link)
    {

        if (link.index >= pow(2, link.branch.size()))
        {
            throw std::invalid_argument("index too large");
        }

        int i = 0;

        auto res = std::accumulate(link.branch.begin(), link.branch.end(), tip_hash,
                                   [&] (const uint256 &c, const uint256 &h){
                                       merkle_record_type merkle_rec;
                                       if ((link.index >> i) & 1)
                                       {
                                           merkle_rec = merkle_record_type{h, c};
                                       } else {
                                           merkle_rec = merkle_record_type{c, h};
                                       }

                                       PackStream ps;
                                       ps << merkle_rec;
                                       auto result = hash256(ps, true);
                                       i++;
                                       return result;
                                    }
                                   );

        return res;
    }

    uint256 merkle_hash(std::vector<uint256> hashes)
    {
        if (hashes.empty())
            return uint256();

        while(hashes.size() > 1)
        {
            std::vector<uint256> new_hashes;

            std::vector<uint256> evens = math::every_nth_element(hashes.begin(), hashes.end(), 2);

            std::vector<uint256> odds = math::every_nth_element(hashes.begin() + 1, hashes.end(), 2);
            odds.push_back(evens.back());

            uint256 left, right;
            BOOST_FOREACH(boost::tie(left, right), boost::combine(evens, odds))
                        {
                            merkle_record_type record(left, right);
                            PackStream _stream;
                            _stream << record;
                            uint256 _hash = hash256(_stream);

                            new_hashes.push_back(_hash);
                        }
        }
        return hashes.front();
    }

    uint256 get_witness_commitment_hash(uint256 witness_root_hash, uint256 witness_reserved_value)
    {
        merkle_record_type record(witness_root_hash, witness_reserved_value);
        PackStream _stream;
        _stream << record;
        return hash256(_stream);
    }
}