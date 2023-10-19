#pragma once

#include <libdevcore/db.h>
#include <libdevcore/filesystem.h>
#include <networks/network.h>

#include "share.h"
#include "data.h"

#include <utility>
#include <fstream>
#include <sstream>

struct ShareTypeStream : Getter<PackedShareData>
{
    ShareTypeStream() = default;

    ShareTypeStream(const ShareType &share)
    {
        value = pack_share(share);
    }

    PackStream &write(PackStream &stream)
    {
        stream << value;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> value;
        return stream;
    }

};

class ShareStore
{
private:
    std::shared_ptr<c2pool::Network> net;

	unique_ptr<Database<IntType(256), ShareTypeStream>> shares;
	unique_ptr<Database<IntType(256), ShareTypeStream>> verified_shares;
public:
    ShareStore() = delete;

    ShareStore(std::shared_ptr<c2pool::Network> _net) : net(std::move(_net))
    {
        auto filepath = c2pool::filesystem::getProjectPath() / net->net_name;

        shares = std::make_unique<Database<IntType(256), ShareTypeStream>>(filepath, "shares");
        verified_shares = std::make_unique<Database<IntType(256), ShareTypeStream>>(filepath, "shares_verified");
    }

public:
	void add_share(const ShareType& share)
	{
        if (!share)
        {
            LOG_WARNING << "try to add nullptr share!";
            return;
        }

		shares->Write(share->hash, share);
	}

	void add_verified(const ShareType& share)
	{
        if (!share)
        {
            LOG_WARNING << "try to add nullptr verified share!";
            return;
        }

        verified_shares->Write(share->hash, share);
	}

    // read file from p2pool
    void legacy_init(const boost::filesystem::path &filepath, std::function<void(std::vector<ShareType>, std::vector<uint256>)> init_f)
    {
        std::vector<ShareType> _shares;
        std::vector<uint256> _known_verified;

        auto file = std::fstream(filepath.c_str(), std::ios_base::in);
        if (file.is_open())
        {
            std::string line;
            int i = 0; //REMOVE
            while(getline(file, line))
            {
                std::stringstream ss(line);

                int type_id;
                std::string data_hex;

                ss >> type_id;
                ss >> data_hex;

                switch (type_id)
                {
                    case 0:
                    case 1:
                        break;
                    case 2:
                    {
                        auto verified_hash = uint256S(data_hex);
                        _known_verified.push_back(verified_hash);
                        break;
                    }
                    case 5:
                    {
                        PackStream stream(ParseHex(data_hex));
//                        PackedShareData raw_share;
//                        stream >> raw_share;
//
//                        if (raw_share.type.get() < 17)
//                            continue;
                        auto share = load_share(stream, net, {{}, {}});
                        share->time_seen = 0;
                        _shares.push_back(std::move(share));
                        break;
                    }
                    default:
                        //TODO raise
                        LOG_ERROR << "NotImplementedError(ShareType " << type_id << ").";
                        break;
                }



                i++; //REMOVE
//                if (i >= 2601)
//                if (i >= 34561)
                if (i >= 17508)
//                if (i >= 20)
                    break;
            }


        }
        file.close();

        init_f(_shares, _known_verified);
    }

    ShareType get_share(const uint256 &hash)
    {
        if (!shares->Exist(hash))
        {
            throw std::invalid_argument((boost::format("Shares exisn't for %1% hash") % hash.GetHex()).str());
        }

        auto readed_share = shares->Read(hash);
        auto packed_share = pack_to_stream<ShareTypeStream>(readed_share);
        auto share = load_share(packed_share, net, {"0.0.0.0", "0"});
        return share;
    }

    ShareType get_verified_share(const uint256 &hash)
    {
        if (!verified_shares->Exist(hash))
        {
            throw std::invalid_argument((boost::format("Verified shares exisn't for %1% hash") % hash.GetHex()).str());
        }

        auto packed_share = pack_to_stream<ShareTypeStream>(verified_shares->Read(hash));
        auto share = load_share(packed_share, net, {"0.0.0.0", "0"});
        return share;
    }
};

