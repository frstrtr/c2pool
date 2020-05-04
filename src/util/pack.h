#ifndef CPOOL_PACK_H
#define CPOOL_PACK_H

#include <iostream>
#include <sstream>
#include <cmath>
#include <pystruct.h>
#include <vector>

namespace c2pool::pack
{
    enum PackTypes
    { //У этих же типов в p2pool - окончание Type.
        Int,
        BitcoinDataAddress, //value = [services; address; port]
        VarStr,
        PossiblyNone,
        Composed
    };

    class ComposedType
    {
        stringstream fields;

    private:
        void Space();

    public:
        ComposedType();

        string read();

        template <typename T>
        ComposedType &add(const T &value)
        {
            Space();
            fields << value;
            return *this;
        }

        template <typename T>
        ComposedType &add(const vector<T> value)
        {
            Space();
            fields << "[";
            for (int i = 0; i < value.size(); i++)
            {
                if (i != 0)
                {
                    fields << ","; //элементы массива разделяются запятой!
                }
                fields << value[i];
            }
            fields << "]";
            return *this;
        }
    };
} // namespace c2pool::pack

#endif //CPOOL_PACK_H
