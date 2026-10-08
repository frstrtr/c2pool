// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Minimal, dependency-free JSON reader (objects/arrays/strings/numbers/bool/
// null) shared by the Family-A full-file importers. Deliberately small: wallet
// files (Electrum, generic keystores) are ASCII and shallow, so we keep the
// permissive ASCII-subrange \u handling of the M1-A keystore parser rather than
// pulling nlohmann/json into this Qt-free leaf module.

#include <string>
#include <utility>
#include <vector>

namespace c2w::hdkeys::mjson {

struct JVal {
    enum class T { Null, Bool, Num, Str, Arr, Obj } t = T::Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<JVal> arr;
    std::vector<std::pair<std::string, JVal>> obj;   // insertion order preserved

    bool is_obj() const { return t == T::Obj; }
    bool is_arr() const { return t == T::Arr; }
    bool is_str() const { return t == T::Str; }
    // Case-sensitive lookup on an object; nullptr if absent or not an object.
    const JVal* find(const std::string& key) const;
    // Convenience: the string value of a child field, or "" if absent/non-string.
    std::string str_of(const std::string& key) const;
};

// Parse a whole JSON document. ok=false on syntax error (or trailing garbage).
struct ParseResult { bool ok = false; JVal root; std::string error; };
ParseResult parse(const std::string& s);

} // namespace c2w::hdkeys::mjson
