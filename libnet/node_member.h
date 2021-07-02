#pragma once
#include <memory>
using std::shared_ptr;

namespace coind
{
    class ParentNetwork;
    namespace jsonrpc
    {
        class Coind;
    }
}
namespace c2pool
{
    class Network;
    namespace dev
    {
        class coind_config;
        class AddrStore;
    }
    namespace libnet
    {
        class NodeManager;
        namespace p2p
        {
            class P2PNode;
        }
    }
    namespace shares
    {
        class ShareTracker;
    }
}

namespace c2pool::libnet
{
    class INodeMember
    {
    public:
        const shared_ptr<c2pool::libnet::NodeManager> manager;

        INodeMember(shared_ptr<c2pool::libnet::NodeManager> mng);
        INodeMember(const INodeMember &member);

    public:
        shared_ptr<c2pool::Network> net() const;

        shared_ptr<coind::ParentNetwork> netParent() const;

        shared_ptr<c2pool::dev::coind_config> config() const;

        shared_ptr<c2pool::dev::AddrStore> addr_store() const;

        shared_ptr<coind::jsonrpc::Coind> coind() const;

        shared_ptr<c2pool::libnet::p2p::P2PNode> p2pNode() const;

        shared_ptr<c2pool::shares::ShareTracker> tracker() const;
    };
} // namespace c2pool::libnet