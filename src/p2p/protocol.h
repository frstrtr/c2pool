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

            addr = make_tuple(self.transport.getPeer().host, self.transport.getPeer().port); //todo: self.transoprt = socket?

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

            /* TODO: create delegates
        def add_to_remote_view_of_my_known_txs(added):
            if added:
                self.send_have_tx(tx_hashes=list(added.keys()))

        watch_id0 = self.node.known_txs_var.added.watch(add_to_remote_view_of_my_known_txs)
        self.connection_lost_event.watch(lambda: self.node.known_txs_var.added.unwatch(watch_id0))

        def remove_from_remote_view_of_my_known_txs(removed):
            if removed:
                self.send_losing_tx(tx_hashes=list(removed.keys()))

                # cache forgotten txs here for a little while so latency of "losing_tx" packets doesn't cause problems
                key = max(self.known_txs_cache) + 1 if self.known_txs_cache else 0
                self.known_txs_cache[key] = removed #dict((h, before[h]) for h in removed)
                reactor.callLater(20, self.known_txs_cache.pop, key)
        watch_id1 = self.node.known_txs_var.removed.watch(remove_from_remote_view_of_my_known_txs)
        self.connection_lost_event.watch(lambda: self.node.known_txs_var.removed.unwatch(watch_id1))

        def update_remote_view_of_my_known_txs(before, after):
            t0 = time.time()
            added = set(after) - set(before)
            removed = set(before) - set(after)
            if added:
                self.send_have_tx(tx_hashes=list(added))
            if removed:
                self.send_losing_tx(tx_hashes=list(removed))

                # cache forgotten txs here for a little while so latency of "losing_tx" packets doesn't cause problems
                key = max(self.known_txs_cache) + 1 if self.known_txs_cache else 0
                self.known_txs_cache[key] = dict((h, before[h]) for h in removed)
                reactor.callLater(20, self.known_txs_cache.pop, key)
            t1 = time.time()
            if p2pool.BENCH and (t1-t0) > .01: print "%8.3f ms for update_remote_view_of_my_known_txs" % ((t1-t0)*1000.)
        watch_id2 = self.node.known_txs_var.transitioned.watch(update_remote_view_of_my_known_txs)
        self.connection_lost_event.watch(lambda: self.node.known_txs_var.transitioned.unwatch(watch_id2))

        self.send_have_tx(tx_hashes=self.node.known_txs_var.value.keys())

        def update_remote_view_of_my_mining_txs(before, after):
            t0 = time.time()
            added = set(after) - set(before)
            removed = set(before) - set(after)
            if removed:
                self.send_forget_tx(tx_hashes=list(removed))
                self.remote_remembered_txs_size -= sum(100 + bitcoin_data.tx_type.packed_size(before[x]) for x in removed)
            if added:
                self.remote_remembered_txs_size += sum(100 + bitcoin_data.tx_type.packed_size(after[x]) for x in added)
                assert self.remote_remembered_txs_size <= self.max_remembered_txs_size
                fragment(self.send_remember_tx, tx_hashes=[x for x in added if x in self.remote_tx_hashes], txs=[after[x] for x in added if x not in self.remote_tx_hashes])
            t1 = time.time()
            if p2pool.BENCH and (t1-t0) > .01: print "%8.3f ms for update_remote_view_of_my_mining_txs" % ((t1-t0)*1000.)

        watch_id2 = self.node.mining_txs_var.transitioned.watch(update_remote_view_of_my_mining_txs)
        self.connection_lost_event.watch(lambda: self.node.mining_txs_var.transitioned.unwatch(watch_id2))

        self.remote_remembered_txs_size += sum(100 + bitcoin_data.tx_type.packed_size(x) for x in self.node.mining_txs_var.value.values())
        assert self.remote_remembered_txs_size <= self.max_remembered_txs_size
        fragment(self.send_remember_tx, tx_hashes=[], txs=self.node.mining_txs_var.value.values())
             */
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

                    vector<c2pool::messages::address_type> adr = {c2pool::messages::address_type(other_services, host, port)};
                    int timestamp = ;//TODO: INIT
                    c2pool::messages::message_addrs msg = c2pool::messages::message_addrs(adr, timestamp);
                    sendPacket(msg);
                } else {
                    if (Log::DEBUG) {
                        Log::Debug("Advertising for incoming connections");
                        send_addrme(port);
                    }
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
                /* TODO: random
                    if random.random() < .8 and self.node.peers:
                        random.choice(self.node.peers.values()).send_addrme(port=port) # services...
                 */
                if ((c2pool::random::RandomFloat(0, 1) < 0.8) && node->peers != null){ // TODO: вместо != null, size() == 0???
                    c2pool::random::RandomChoice(node->peers).send_addrme(port);
                }
            } else {
                //self.node.got_addr((self.transport.getPeer().host, port), self.other_services, int(time.time()))
                if ((c2pool::random::RandomFloat(0, 1) < 0.8) && node->peers != null){ // TODO: вместо != null, size() == 0???
                    /*random.choice(self.node.peers.values()).send_addrs(addrs=[
                    dict(
                        address=dict(
                            services=self.other_services,
                            address=host,
                            port=port,
                        ),
                        timestamp=int(time.time()),
                    ),
                ])
                 */
                    c2pool::random::RandomChoice(node->peers).send_addrs(/*todo*/);
                }
            }
        }

        void handle_getaddrs(int count){
            if (count > 100){
                count = 100;
            }
            for ()
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
