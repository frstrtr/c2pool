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
#include <map>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include "log.cpp"
#include "converter.cpp"
#include "other/other.cpp"

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
                Log::Debug("no type for ", false);
                Log::Debug(command);
            }

            packetReceived(msg);



        }

        void packetReceived(message* msg){
            msg->handle(this);
        }



    private:
        Factory* factory;
        tcp::socket socket;
        const unsigned long max_remembered_txs_size = 25000000;
        unsigned long max_payload_length;

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

            //self.connection_lost_event = variable.Event()

            //TODO: getPeer() and getHost()
            addr = make_tuple(socket.remote_endpoint().address().to_string(), socket.remote_endpoint().port().to_string()); //todo: move remote_endpoint to method

            send_version(version, 0, c2pool::messages::address_type(0, socket.remote_endpoint().address(), socket.remote_endpoint().port()),
                         c2pool::messages::address_type(0, gethost, gethost), node->nonce, /*todo: p2pool.__version__*/, 1, /*node->best_share_hash_func*/)
            //_____________

            //todo: self.timeout_delayed = reactor.callLater(10, self._connect_timeout)


            /*
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

        auto connect_timeout(){
            timeout_delayed = null; //todo: ?
            //TODO: Log.Write(Handshake timed out, disconnecting from %s:%i) /  print 'Handshake timed out, disconnecting from %s:%i' % self.addr
            disconnect();
        }


        void send_version(int ver, int serv, address_type to, address_type from, long _nonce, string sub_ver, int _mode, long best_hash){
            c2pool::messages::message_version msg = c2pool::messages::message_version(ver, serv, to, from, _nonce, sub_ver, _mode, best_hash);
            sendPacket(msg);
        }

        void handle_version(int ver, int serv, address_type to, address_type from, long _nonce, string sub_ver, int _mode, long best_hash) {

            cout << "Peer " << from.address << ":" << from.port << " says protocol version is " << ver << ", client version " << sub_ver;

            if (other_version != -1) {
                //TODO: DEBUG: raise PeerMisbehavingError('more than one version message')
            }
            if (ver < c2pool::config::MINIMUM_PROTOCOL_VERSION){
                //TODO: DEBUG: raise PeerMisbehavingError('peer too old')
            }

            other_version = ver;
            other_sub_version = sub_ver;
            other_services = serv;

            if (_nonce == node->nonce){ //TODO: add nonce in Node
                //TODO: DEBUG: raise PeerMisbehavingError('was connected to self')
            }

            if ([_nonce in node->peers]){ //TODO: detect duplicate in node->peers
                string err = "Detected duplicate connection, disconnecting from " + addr.get<0>() + ":" + to_string(addr.get<1>());
                Log::Debug(err);
                disconnect();
                //return; //TODO: remove comment, when fix: [_nonce in node->peers]
            }

            nonce = _nonce;
            connected2 = true;

            /* TODO: BOOST TIMER
                self.timeout_delayed.cancel()
                self.timeout_delayed = reactor.callLater(100, self._timeout)
             */

            /* TODO: TIMER + DELEGATE
             old_dataReceived = self.dataReceived
        def new_dataReceived(data):
            if self.timeout_delayed is not None:
                self.timeout_delayed.reset(100)
            old_dataReceived(data)
        self.dataReceived = new_dataReceived
             */

            factory->proto_connected(this);

            /* TODO: thread (coroutine?):
             self._stop_thread = deferral.run_repeatedly(lambda: [
            self.send_ping(),
        random.expovariate(1/100)][-1])

             if self.node.advertise_ip:
            self._stop_thread2 = deferral.run_repeatedly(lambda: [
                self.sendAdvertisement(),
            random.expovariate(1/(100*len(self.node.peers) + 1))][-1])
             */

            if (best_hash != -1){ // -1 = None
                node->handle_share_hashes([best_hash], this); //TODO: best_share_hash in []?
            }
        }

        void sendAdvertisement(){
            if (node->server->listen_port /*TODO: is not None*/){
                string host = node->external_ip; //todo: add node.external_ip
                int port = node->server->listen_port(/*???*/); //TODO
                if (host != ""){
                    if (host.find(":") != string::npos){
                        vector<string> res;

                        boost::split(res, host, [](char c){return c == ':';});
                        host = res[0];
                        port = Converter::StrToInt(res[1]);
                    }

                    string err = "Advertising for incoming connections: " + host + ":" + to_string(port);
                    Log::Debug(err);


                    int timestamp = c2pool::time::timestamp();
                    vector<c2pool::messages::addrs> adr = {c2pool::messages::addrs(c2pool::messages::address_type(other_services, host, port), timestamp)};
                    send_addrs(adr);
                } else {
                    if (Log::DEBUG) {
                        Log::Debug("Advertising for incoming connections");
                        send_addrme(port);
                    }
                }
            }
        }

        void send_addrs(vector<c2pool::messages::addrs> _addrs){
            c2pool::messages::message_addrs msg = c2pool::messages::message_addrs(_addrs);
            sendPacket(msg);
        }

        void handle_addrs(vector<c2pool::messages::addr> addrs){
            for (auto data : addrs){
                node->got_addr(data, c2pool::time::timestamp());
                if ((c2pool::random::RandomFloat(0,1) < 0.8) && node->peers != nullptr){ // TODO: вместо != null, size() == 0???
                    c2pool::random::RandomChoice(*node->peers).send_addrs(vector<c2pool::messages::addrs> buff{data});
                }
            }
        }

        void send_addrme(int port){
            c2pool::messages::message_addrme msg = c2pool::messages::message_addrme(port); //in if from todo debug
            sendPacket(msg);
        }

        void handle_addrme(int port){
            string host = ; //TODO: self.transport.getPeer().host

            if (host == "127.0.0.1"){
                if ((c2pool::random::RandomFloat(0, 1) < 0.8) && node->peers != null){ // TODO: вместо != null, size() == 0???
                    c2pool::random::RandomChoice(*node->peers).send_addrme(port);
                }
            } else {
                c2pool::messages::addr _addr(other_services, socket.remote_endpoint().address().to_string(), port, c2pool::time::timestamp()) //TODO: move remote_endpoint to method
                if ((c2pool::random::RandomFloat(0, 1) < 0.8) && node->peers != null){ // TODO: вместо != null, size() == 0???
                    vector<c2pool::messages::addr _addr2(other_services, host, port, c2pool::time::timestamp())
                    c2pool::random::RandomChoice(node->peers).send_addrs(_addr2);
                }
            }
        }


        void send_ping(){
            c2pool::messages::message_ping msg = c2pool::messages::message_ping();
            sendPacket(msg);
        }

        void handle_ping(long long _nonce){
            //pass
        }

        void send_getaddrs(int _count){
            c2pool::messages::message_getaddrs msg = c2pool::messages::message_getaddrs(_count);
            sendPacket(msg);
        }

        void handle_getaddrs(int count){//todo: доделать
            if (count > 100){
                count = 100;
            }
            vector<string> good_peers = node->get_good_peers(count); //TODO: type for vector
            vector<c2pool::messages::addr> addrs;
            for (i = 0; i < count; i++){ //todo: доделать
                c2pool::messages::addr buff_addr = c2pool::messages::addr(
                        c2pool::messages::address_type(
                                node->addr_store[good_peers[i]][0], //todo: array index
                                host,
                                port
                                ),
                        node->addr_store[host, port][2]//todo: array index
                        );
            }
            vector<c2pool::messages::address_type> adr = {c2pool::messages::address_type(other_services, host, port)};
            int timestamp = ;//TODO: INIT
            c2pool::messages::message_addrs msg = c2pool::messages::message_addrs(adr, timestamp);
        }
    private:
        P2PNode*_node;

        const unsigned int version;
        unsigned int other_version = -1;
        string other_sub_version;
        int other_services; //TODO: int64? IntType(64)

        bool connected2 = false;
        tuple<string, int> addr; //TODO
        boost::asio::steady_timer timeout_delayed; //Таймер для автодисконнекта, если нет никакого ответа в течении работы таймера. Сбрасывается каждый раз, как получает какие-то пакеты.
        //TODO???: remote_tx_hashes = set() # view of peer's known_txs # not actually initially empty, but sending txs instead of tx hashes won't hurt
        int remote_remembered_txs_size = 0; //todo: remove?

        map<string, /*TODO*/> remembered_txs = null; ////TODO: type of key+vakue;  view of peer's mining_txs [78]
        int = remembered_txs_size = 0 [79]
        map<string, /*TODO*/> known_txs_cache = null; //TODO: type of key+vakue

        int nonce; //TODO: int64? IntType(64)

    };
}

#endif //CPOOL_PROTOCOL_H
