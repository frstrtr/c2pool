#pragma once

#include <vector>

#include <core/pack.hpp>

using BaseScript = std::vector<unsigned char>;

class OPScript : public BaseScript
{
public:
    OPScript() {}
    OPScript(const_iterator pbegin, const_iterator pend) : BaseScript(pbegin, pend) { }
    OPScript(const unsigned char* pbegin, const unsigned char* pend) : BaseScript(pbegin, pend) { }

    SERIALIZE_METHODS(OPScript) { READWRITE(AsBase<BaseScript>(obj)); }
};

struct OPScriptWitness
{
    // Note that this encodes the data elements being pushed, rather than
    // encoding them as a CScript that pushes them.
    std::vector<std::vector<unsigned char> > stack;

    // Some compilers complain without a default constructor
    OPScriptWitness() { }

    bool IsNull() const { return stack.empty(); }

    void SetNull() { stack.clear(); stack.shrink_to_fit(); }

    // inline std::string ToString() const
    // {
    //     std::string ret = "CScriptWitness(";
    //     for (unsigned int i = 0; i < stack.size(); i++) {
    //         if (i) {
    //             ret += ", ";
    //         }
    //         ret += HexStr(stack[i]);
    //     }
    //     return ret + ")";
    // }
};