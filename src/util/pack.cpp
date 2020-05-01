#include "pack.h"
#include <iostream>
using namespace std;

namespace c2pool::pack
{

    void ComposedType::Space()
    { // проверка и разделение переменных в потоке.
        if (fields.rdbuf()->in_avail() != 0)
        { //проверка на то, что в fields уже есть какие-то данные.
            fields << ";";
        }
    }

    ComposedType::ComposedType()
    {
        fields.clear();
    }

    string ComposedType::read()
    {
        string buff;
        fields >> buff;
        string res = buff;
        return res;
    }

} // namespace p2pool::pack