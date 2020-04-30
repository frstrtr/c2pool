//
// Created by vasil on 17.03.2020.
//

#ifndef CPOOL_MESSAGES_H
#define CPOOL_MESSAGES_H


#include <iostream>
#include "types.h"
#include "pack.h"

namespace c2pool::p2p {
    class Protocol;
}
using namespace std;
using namespace c2pool::p2p;

namespace c2pool::messages{

    enum Messages{
        error = 9999,
        version = 0
    };

    class message{
    public:
        std::string command;

        message(std::string cmd);

        void unpack(std::string item);

        string pack();

        virtual void _unpack(stringstream& ss);
        virtual string _pack();
        virtual void handle(p2p::Protocol* protocol);
    };
    
    message* fromStr(string str);

    class message_error: public message{
    public:
        message_error(const string cmd = "error");
    };

    class message_version: public message{
    public:

        message_version(int ver, int serv, address_type to, address_type from, long _nonce, string sub_ver, int _mode, long best_hash, const string cmd = "version");

        void _unpack(stringstream& ss) override {
            ss >> version >> services >> addr_to >> addr_from >> nonce >> sub_version >> mode >> best_share_hash;

            //TODO: override operator >> for address_type;
        }

        string _pack() override{
            ComposedType ct;
            ct.add(version);
            ct.add(services);
            ct.add(addr_to);
            ct.add(addr_from);
            ct.add(nonce);
            ct.add(sub_version);
            ct.add(mode);
            ct.add(best_share_hash);
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_version(/*todo*/);
        }


        //= pack.ComposedType([
        //     ('version', pack.IntType(32)),
        int version;
        //     ('services', pack.IntType(64)),
        int services;
        //     ('addr_to', bitcoin_data.address_type),
        address_type addr_to;
        //     ('addr_from', bitcoin_data.address_type),
        address_type addr_from;
        //     ('nonce', pack.IntType(64)),
        long nonce;
        //     ('sub_version', pack.VarStrType()),
        string sub_version;
        //     ('mode', pack.IntType(32)), # always 1 for legacy compatibility
        int mode;
        //     ('best_share_hash', pack.PossiblyNoneType(0, pack.IntType(256))),
        long best_share_hash; // TODO: long long?
        // ])
    };

    class message_ping: public message{
    public:

        message_ping(const string cmd = "ping") : message(cmd) {}
        
        
        void _unpack(stringstream& ss) override {
            ss >> // todo Empty variables list

        }

        string _pack() override{
            ComposedType ct;
            ct.add(command);
            return ct.read();

        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_ping(/*todo*/);
        }

        // message_ping = pack.ComposedType([])
        //todo Empty list

    };

    class message_addrme: public message{
    public:

        message_addrme(int _port, const string cmd = "addrme"):message(cmd){
            port = _port;
        }

        void _unpack(stringstream& ss) override {
            ss >> port;
        }

        string _pack() override{
            ComposedType ct;
            ct.add(port);
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_addrme(/*todo*/);
        }

        //= pack.ComposedType([
        //    ('port', pack.IntType(16)),
        int port;
        //])        
    };

    class message_getaddrs: public message{
    public:

        message_getaddrs(int cnt, const string cmd = "getaddr"):message(cmd){
            count = cnt;
        }

        void _unpack(stringstream& ss) override {
            ss >> count;
        }

        string _pack() override{
            ComposedType ct;
            ct.add(count);
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_getaddrs(/*todo*/);
        }

        //     = pack.ComposedType([
        //     ('count', pack.IntType(32)),
        int count;
        // ])
    };

    class message_addrs: public message{
    public:

        message_addrs(vector<addr> _addrs, const string cmd = "addrs"): message(cmd){
            addrs = _addrs;
        }

        void _unpack(stringstream& ss) override {
            int count;
            addr addrBuff;
            ss >> count;
            for (int i = 0; i < count; i++) {
                ss >> addrBuff;
                addrs.push_back(addrBuff);
            }
        }

        string _pack() override{
            ComposedType ct;
            ct.add(addrs); //TODO: override operator << for this
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_addrs(/*todo*/);
        }
        

        vector<addr> addrs;

        // = pack.ComposedType([
        //     ('addrs', pack.ListType(pack.ComposedType([
        //         ('timestamp', pack.IntType(64)),
        //         ('address', bitcoin_data.address_type),
        //     ]))),
        // ])
        
    };









    //__________________________
    class message_shares: public message{
    public:

        message_shares(share_type shrs, const string cmd = "version"):message(cmd){
            shares = shrs;
        }

        void _unpack(stringstream& ss) override {
            ss >> shares;

            //TODO: override operator >> for share_type;
        }

        string pack() override{
            ComposedType ct;
            ct.add(shares.ToString());//todo check toString()
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_shares(/*todo*/);
        }

        //     = pack.ComposedType([
        //     ('shares', pack.ListType(p2pool_data.share_type)),
        share_type shares;
        // ])
    };

    class message_sharereq: public message{// TODO переделать ListType.
    public:

        message_sharereq(int idd, ???ListType_Int256 hshs, int prnts, ???ListType_Int256 stps, const string cmd = "version"):message(cmd){
            id = idd;
            hashes = hshs;
            parents = prnts;
            stops = stps;
        }

        void _unpack(stringstream& ss) override {
            ss >> id >> hashes >> parents >> stops;

            //TODO: override operator >> for ListType_Int256;
        }

        string _pack() override{
            ComposedType ct;
            ct.add(id);
            ct.add(hashes.ToString());//todo check ListType_Int256, hashes.ToString()
            ct.add(parents);
            ct.add(stops.ToString());//todo ListType_Int256, stops.ToString()
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_sharereq(/*todo*/);
        }

        //     = pack.ComposedType([
        //     ('id', pack.IntType(256)),
        int id;
        //     ('hashes', pack.ListType(pack.IntType(256))),
        ListType_Int256 hashes;
        //     ('parents', pack.VarIntType()),
        int parents;
        //     ('stops', pack.ListType(pack.IntType(256))),
        ListType_Int256 stops;
        // ])
    };

    class message_sharereply: public message{// TODO Enum и ListTypeShareType
    public:

        message_sharereply(int idd, enum rslt, ListTypeShareType shrs, const string cmd = "version"):message(cmd){
            id = idd;
            result = rslt;
            shares = shrs;
        }

        void _unpack(stringstream& ss) override {
            ss >> id >> result >> shares;

            //TODO: override operator >> for ListTypeShareType & enum;
        }

        string _pack() override{
            ComposedType ct;
            ct.add(id);
            ct.add(result); //todo check enum
            ct.add(shares);// todo check ListTypeShareType
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_sharereply(/*todo*/);
        }
        
        //     = pack.ComposedType([
        //     ('id', pack.IntType(256)),
        int id;
        //     ('result', pack.EnumType(pack.VarIntType(), {0: 'good', 1: 'too long', 2: 'unk2', 3: 'unk3', 4: 'unk4', 5: 'unk5', 6: 'unk6'})),
        enum result;// TODO enum?
        //     ('shares', pack.ListType(p2pool_data.share_type)),
        ListTypeShareType shares;// TODO ListType
        // ])
    };

    class message_bestblock: public message{// TODO BitcoinDataBlockHeaderType
    public:

        message_bestblock(BitcoinDataBlockHeaderType hdr, const string cmd = "version"):message(cmd){
            header = hdr;

            //TODO: override operator >> for BitcoinDataBlockHeaderType;
        }

        void _unpack(stringstream& ss) override {
            ss >> header;
        }

        string _pack() override{
            ComposedType ct;
            ct.add(header.ToString());//todo check BitcoinDataBlockHeaderType
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_bestblock(/*todo*/);
        }

        //     = pack.ComposedType([
        //     ('header', bitcoin_data.block_header_type),
        BitcoinDataBlockHeaderType header;
        // ])
    };

    class message_have_tx: public message{
    public:

        message_have_tx(int tx_hshs, const string cmd = "version"):message(cmd){
            tx_hashes = tx_hshs;
        }

        void _unpack(stringstream& ss) override {
            ss >> tx_hashes;
        }

        string _pack() override{
            ComposedType ct;
            ct.add(tx_hashes);
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_have_tx(/*todo*/);
        }

        //     = pack.ComposedType([
        //     ('tx_hashes', pack.ListType(pack.IntType(256))),
        int tx_hashes;
        // ])
    };

    class message_losing_tx: public message{// TODO ListTypeInt256
    public:

        message_losing_tx(ListTypeInt256 tx_hshs, const string cmd = "version"):message(cmd){
            tx_hashes = tx_hshs;
        }

        void _unpack(stringstream& ss) override {
            ss >> tx_hashes;

            //todo override operator >> for ListTypeInt256
        }

        string _pack() override{
            ComposedType ct;
            ct.add(tx_hashes);//todo check ListTypeInt256
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_losing_tx(/*todo*/);
        }

        //     = pack.ComposedType([
        //     ('tx_hashes', pack.ListType(pack.IntType(256))),
        ListTypeInt256 tx_hashes;
        // ])
    };

    class message_remember_tx: message{// TODO ListTypeInt256, ListTypeTX
    public:

        message_remember_tx(ListTypeInt256 tx_hshs, ListTypeTX txss, const string cmd = "version"):message(cmd){
            tx_hashes = tx_hshs;
            txs = txss;
        }

        void _unpack(stringstream& ss) override {
            ss >> tx_hashes >> txs;

            //todo override operator >> forListTypeInt256, ListTypeTX
        }

        string _pack() override{
            ComposedType ct;
            ct.add(tx_hashes);//todo ListTypeInt256
            ct.add(txs);//todo ListTypeTX
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_remember_tx(/*todo*/);
        }

        //     = pack.ComposedType([
        //     ('tx_hashes', pack.ListType(pack.IntType(256))),
        ListTypeInt256 tx_hashes;
        //     ('txs', pack.ListType(bitcoin_data.tx_type)),
        ListTypeTX txs;
        // ])
    };

    class message_forget_tx: message {// TODO ListTypeInt256
    public:

        message_forget_tx(ListTypeInt256 tx_hshs, const string cmd = "version"):message(cmd){
            tx_hashes = tx_hshs;
        }

        void _unpack(stringstream& ss) override {
            ss >> tx_hashes;
            //todo override operator >> for ListTypeInt256
        }

        string _pack() override{
            ComposedType ct;
            ct.add(tx_hashes);//todo ListTypeInt256
            return ct.read();
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_forget_tx(/*todo*/);
        }

        //     = pack.ComposedType([
        //     ('tx_hashes', pack.ListType(pack.IntType(256))),
        ListTypeInt256 tx_hashes;
        // ])
    }

    //__________________________
}


#endif //CPOOL_MESSAGES_H
