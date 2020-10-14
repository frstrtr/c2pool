#include <share.h>
#include <config.h>
#include <memory>

namespace c2pool::shares
{
    bool is_segwit_activated(int version, int segwit_activation_version){
        return (segwit_activation_version > 0) && (version >= segwit_activation_version);
    }

    BaseShare::BaseShare(shared_ptr<c2pool::config::Network> _net, auto _peer_addr, auto _contents)
    {
        net = _net;
        peer_addr = _peer_addr;
        contents = _contents;
    }

} // namespace c2pool::shares