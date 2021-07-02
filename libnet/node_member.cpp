#include "node_member.h"
#include "nodeManager.h"
#include <memory>

using namespace std;

namespace c2pool::libnet
{
    INodeMember::INodeMember(shared_ptr<c2pool::libnet::NodeManager> mng) : manager(mng)
    {
    }

    INodeMember::INodeMember(const INodeMember &member) : manager(member.manager)
    {
    }

    shared_ptr<c2pool::Network> INodeMember::net() const
    {
        return manager->net();
    }

    shared_ptr<coind::ParentNetwork> INodeMember::netParent() const
    {
        return manager->netParent();
    }

    shared_ptr<c2pool::dev::coind_config> INodeMember::config() const
    {
        return manager->config();
    }

    shared_ptr<c2pool::dev::AddrStore> INodeMember::addr_store() const
    {
        return manager->addr_store();
    }

    shared_ptr<coind::jsonrpc::Coind> INodeMember::coind() const
    {
        return manager->coind();
    }

    shared_ptr<c2pool::libnet::p2p::P2PNode> INodeMember::p2pNode() const
    {
        return manager->p2pNode();
    }

    shared_ptr<c2pool::shares::ShareTracker> INodeMember::tracker() const
    {
        return manager->tracker();
    }

}
