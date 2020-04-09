//
// Created by vasil on 17.03.2020.
//

#ifndef CPOOL_MESSAGES_H
#define CPOOL_MESSAGES_H


#include <iostream>
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
        message(string cmd){
            command = cmd;
        }
        string command;
        virtual void unpack(string item);
        virtual string pack();
        virtual void handle(p2p::Protocol* protocol);
    };
    
    message* fromStr(string str);

    class message_error: public message{
    public:
        message_error(const string cmd = "error"):message(cmd){

        }
    };

    class address_type{ //TODO: move to data.cpp
    public:
        /*
            ('services', pack.IntType(64)),
            ('address', pack.IPV6AddressType()),
            ('port', pack.IntType(16, 'big')),
         */

        address_type(int _services, string _address, int _port){
            services = _services;
            address = _address;
            port = _port;
        }

        int services;
        string address; //TODO: change to boost::ip?
        int port;

        string ToString(){
            stringstream ss;
            ss << "[" << services << ";" << address << ";" << port << "]";
            string res;
            ss >> res;
            return res;
        }
    };

    class share_type{ //TODO: move to data.cpp
    public:
        /*
            ('type', pack.VarIntType()),
            ('contents', pack.VarStrType()),
        */
        int type;
        string contents;

        string ToString(){
            stringstream ss;
            ss << "[" << type << ";" << contents << "]";
            string res;
            ss >> res;
            return res;
        }
    };

    class message_version: public message{
    public:

        message_version(int ver, int serv, address_type to, address_type from, long _nonce, string sub_ver, int _mode, long best_hash, const string cmd = "version");

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("version", PackTypes::IntType, "32", version);
            ct.add("services", PackTypes::IntType, "64", services);
            ct.add("addr_to", PackTypes::BitcoinDataAddressType, addr_to.ToString());
            ct.add("addr_from", PackTypes::BitcoinDataAddressType, addr_from.ToString());
            ct.add("nonce", PackTypes::IntType, "64", nonce);
            ct.add("sub_version", PackTypes::VarStrType, sub_version);
            ct.add("mode", PackTypes::IntType, "32", mode);
            ct.add("best_share_hash", PackTypes::PossiblyNoneType, "[0,IntType, 256]", best_share_hash); //TODO: Attr
        }

        void handle(p2p::Protocol* protocol){
            protocol->handle_version(/*TODO*/)
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
        message_ping(){}
        
        
        void unpack(string item) override {

        }

        string pack() override{

        }

        void handle(Protocol* protocol){

        }

        // message_ping = pack.ComposedType([])

    };

    class message_addrme: public message{
    public:

        message_addrme(int _port, const string cmd = "addrme"):message(cmd){
            port = _port;
        }

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("port", PackTypes::IntType, "16", port);
        }

        void handle(Protocol* protocol){

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

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("count", PackTypes::IntType, "32", count);
        }

        void handle(Protocol* protocol){

        }

        //     = pack.ComposedType([
        //     ('count', pack.IntType(32)),
        int count;
        // ])
    };

    class message_addrs: public message{
    public:

        message_addrs(vector<address_type> _addrs, int _timestamp, const string cmd = "addrs"):message(cmd){
            addrs = _addrs;
            timestamp = _timestamp;
        }

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("addrs", PackTypes::???);
            ???;
        }

        void handle(Protocol* protocol){

        }
        

        vector<address_type> addrs;
        int timestamp;

        // = pack.ComposedType([
        //     ('addrs', pack.ListType(pack.ComposedType([
        //         ('timestamp', pack.IntType(64)),
        //         ('address', bitcoin_data.address_type),
        //     ]))),
        // ])
        
    };

    class message_shares: public message{
    public:

        message_shares(share_type shrs, const string cmd = "version"):message(cmd){
            shares = shrs;
        }

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("shares", PackTypes::P2PoolDataShareType, shares.ToString());
        }

        void handle(Protocol* protocol){

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

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("id", PackTypes::IntType, "256", id);
            ct.add("hashes", PackTypes::ListType_Int256, hashes.ToString());
            ct.add("parents", PackTypes::IntType, "", parents);
            ct.add("stops", PackTypes::ListType_Int256, stops.ToString());
        }

        void handle(Protocol* protocol){

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

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("id", PackTypes::IntType, "256", id);
            ct.add("result", PackTypes::enum, "", result);
            ct.add("shares", PackTypes::ListTypeShareType, "", shares);
        }

        void handle(Protocol* protocol){

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
        }

        void unpack(string item) override {

        }


        string pack() override{
            ComposedType ct;
            ct.add("header", PackTypes::BitcoinDataBlockHeaderType, "", header.ToString());
        }

        void handle(Protocol* protocol){

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

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("tx_hashes", PackTypes::IntType, "256", tx_hashes);
        }

        void handle(Protocol* protocol){

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

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("tx_hashes", PackTypes::ListTypeInt256, "256", tx_hashes);
        }

        void handle(Protocol* protocol){

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

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("tx_hashes", PackTypes::ListTypeInt256,"256", tx_hashes);
            ct.add("txs", PackTypes::ListTypeTX,"",txs);
        }

        void handle(Protocol* protocol){

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

        void unpack(string item) override {

        }

        string pack() override{
            ComposedType ct;
            ct.add("tx_hashes", PackTypes::ListTypeInt256, "256". tx_hashes);
        }

        void handle(Protocol* protocol){

        }

        //     = pack.ComposedType([
        //     ('tx_hashes', pack.ListType(pack.IntType(256))),
        ListTypeInt256 tx_hashes;
        // ])
    }
}


#endif //CPOOL_MESSAGES_H
