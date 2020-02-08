#ifndef CPOOL_PACK_H
#define CPOOL_PACK_H

#include <iostream>
#include <typeinfo>

//TODO: remove all auto;

class Type{
public:
    Type(){

    }

    friend bool operator==(const Type& A, const Type& B);
    friend bool operator!=(const Type& A, const Type& B);


};

class VarIntType:Type{

    auto read(auto file) {
        //TODO:
    }

    auto write(auto file, auto item){
        //TODO
    }

};

class VarStrType:Type{
    VarIntType _inner_size;
public:
    auto read(auto file){
        auto length = _inner_size.read(file);
        return file.read(length);
    }

    void write(auto file, auto item){
        _inner_size.write(file, length(item));
        file.write(item);
    }
};

class EnumType:Type{
    auto inner;
    auto pack_to_unpack;
    auto unpack_to_pack;
public:
    EnumType(auto _inner, auto _pack_to_unpack){
        inner = _inner;
        pack_to_unpack = _pack_to_unpack;
        //TODO: UNPACK!!!
    }

    auto read(auto file){
        auto data = inner.read(file);
        //TODO: CHECK DATA IN PACK_TO_UNPACK!
        return pack_to_unpack[data];
    }

    void write(auto file, auto item){
        //TODO: CHECK DATA IN PACK_TO_UNPACK!
        inner.write(file, unpack_to_pack[item]);
    }
};

class ListType:Type{
    VarIntType _inner_size;

    auto type;
    auto mul;

public:

    ListType(auto _type, auto _mul = 1){
        type = _type;
        mul = _mul;
    }

    auto read(auto file);

    void write(auto file, auto item){
        //TODO: assert len(item) % self.mul == 0

        _inner_size.write(file, length(item)/mul)

        //TODO: foreach(subitem in item){type.write(file, subitem)}
    }
};

class StructType:Type{
    auto desc;
    auto length;
public:
    StructType(auto _desc){
        desc = _desc;
        //TODO: length = struct.calcsize(desc);
    }

    auto read(auto file){
        auto data = file.read(length);
        //TODO: return struct.unpack(desc, data)[0]
    }

    void write(auto file, auto item){
        //TODO: file.write(struct.pack(self.desc, item))
    }
};

class IntType:Type{
    //TODO: CREATE
};

class IPV6AddressType:Type{
public:
    auto read(auto file){
        //TODO
    }

    void write(auto file, auto item){
        //TODO
    }
};

class ComposedType:Type{
    list<auto> fields;
    set<auto> fields_names;
    auto record_type;

public:
    ComposedType(auto _fields){
        fields = _fields; //TODO: list(fields)
        //TODO: field_names initialize
        //TODO: recorc_type = get_record(...)
    }

    auto read(auto file){
        auto item = record_type();
        //TODO: foreach key, type in fileds
        return item;
    }

    void write(auto file, auto item){
        //TODO: assert set(item.keys()) >= self.field_names
        //TODO: foreach
    }
};

class PossiblyNoneType:Type {
    auto none_value;
    auto inner;
public:
    PossiblyNoneType(auto _none_value, auto _inner) {
        none_value = _none_value;
        inner = _inner;
    }

    auto read(auto file) {
        auto value = inner.read(file);
        if (value == none_value) {
            return nullptr;
        } else {
            return value;
        }
    }

    void write(auto file, auto item) {
        if (item == none_value) {
            //TODO: raise ValueError('none_value used')
        }
        inner.write(file, item == nullptr ? none_value : item);
    }
};

class FixedStrType:Type{
    auto length;

    FixedStrType(auto _length){
        length = _length;
    }

    auto read(auto file){
        return file.read(length);
    }

    void write(auto file, auto item){
        //TODO: if ... raise
        file.write(item);
    }
};




#endif //CPOOL_PACK_H
