#ifndef CPOOL_PROTOCOL_H
#define CPOOL_PROTOCOL_H

#include "boost/asio.hpp"
#include "factory.h"
#include "node.h"
#include <stdio>
#include <string>
#include "pystruct.h"
#include <sstream>
#include "config.cpp"

namespace c2pool::messages{
    class message;
}
using namespace std;

namespace c2pool::p2p {
    /*
     * TODO future: вынести логику Server и Client протокола в разные классы???
     */
    class BaseProtocol {
    public:

        BaseProtocol(boost::asio::io_context io, unsigned long _max_payload_length, unsigned int _version) : version(_version);

        BaseProtocol(boost::asio::io_context io);

        void sendPacket(c2pool::messages::message *payload2);

        ///called, when start connection
        void connectionMade() = 0;

    private:

        void disconnect(){
            //TODO: ec check??
            boost::system::error_code ec;
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            socket.close(ec);
        }

        void dataReceived(string data){
            size_t prefix_pos = data.find(c2pool::config::PREFIX);
            if (prefix_pos != std::string::npos){
                data = data.substr(prefix_pos + c2pool::config::PREFIX.length());
            } else {
                //TODO: Debug_log: PREFIX NOT FOUND
                return;
            }
            string command = data.substr(0, 12); //TODO: check for '\0'???

            string lengthPacked; //TODO: value?
            int length;
            stringstream ss = pystruct::unpack("<I", lengthPacked);
            ss >> length;
            if (length > max_payload_length){
                //TODO: Debug_log: length too large
            }

            string checksum = data.substr(?,?); //TODO
            string payload = data.substr(?,?); //TODO:

            //TODO: HASH, check for hash function btc-core
            if (hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum){
                //TODO: Debug_log: invalid hash
                disconnect();
                //return; //todo:
            }

            message* msg = c2pool::messages::fromStr(command);

            if (msg->command == "error"){
                //TODO: Debug_log: no type for
                //return
            }

            packetReceived(msg);



        }

        void packetReceived(message* msg){
            msg->handle(this);
        }



    private:
        P2PNode*_node;
        Factory* factory;
        tcp::socket socket;
        const unsigned int version;
        const unsigned long max_remembered_txs_size = 25000000;
        unsigned long max_payload_length;

        boost::asio::steady_timer timeout_delayed; //Таймер для автодисконнекта, если нет никакого ответа в течении работы таймера. Сбрасывается каждый раз, как получает какие-то пакеты.

        friend class Factory;
    };

    class Protocol:public BaseProtocol{
    public:
        Protocol(boost::asio::io_context io, ) : BaseProtocol(io, _max_payload_length, 3301){ //TODO: base constructor

        }

        Protocol(boost::asio::io_context io) : BaseProtocol(io, 3301){ //TODO: base constructor

        }

        void connectionMade(){
            factory->proto_made_connection(this);

            /*self.connection_lost_event = variable.Event()

        self.addr = self.transport.getPeer().host, self.transport.getPeer().port

        self.send_version(
            version=self.VERSION,
            services=0,
            addr_to=dict(
                services=0,
                address=self.transport.getPeer().host,
                port=self.transport.getPeer().port,
            ),
            addr_from=dict(
                services=0,
                address=self.transport.getHost().host,
                port=self.transport.getHost().port,
            ),
            nonce=self.node.nonce,
            sub_version=p2pool.__version__,
            mode=1,
            best_share_hash=self.node.best_share_hash_func(),
        )

        self.timeout_delayed = reactor.callLater(10, self._connect_timeout)

        self.get_shares = deferral.GenericDeferrer(
            max_id=2**256,
            func=lambda id, hashes, parents, stops: self.send_sharereq(id=id, hashes=hashes, parents=parents, stops=stops),
            timeout=15,
            on_timeout=self.disconnect,
        )

        self.remote_tx_hashes = set() # view of peer's known_txs # not actually initially empty, but sending txs instead of tx hashes won't hurt
        self.remote_remembered_txs_size = 0

        self.remembered_txs = {} # view of peer's mining_txs
        self.remembered_txs_size = 0
        self.known_txs_cache = {}*/
        }

        //todo: connect_timeout

        


        void send_version(){
            //TODO: init struct Version
        }

        void handle_version(){

        }
    private:
        bool connected2 = false;


    };
}

#endif //CPOOL_PROTOCOL_H
