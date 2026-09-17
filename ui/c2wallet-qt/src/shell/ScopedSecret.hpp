// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// GAP-7 — the shell-wide RAII secret holder, hoisted out of PageImport /
// PageScan so every screen that must hand a plaintext secret to a library
// function (which takes std::string) wipes it the same way (design §5.3 "Key
// custody": all secrets in zeroizing containers, RAII-wiped on every exit path
// including exceptions; no secret lingers on the heap).
//
// The library key material stays in the zeroizing SecureBytes / MoneroKeys the
// libraries return; this holder covers only the transient std::string that must
// exist because the import/sign entry points take std::string.

#include "secure/SecureString.hpp"

#include <string>
#include <utility>

// RAII holder that securely wipes a plaintext secret std::string when it leaves
// scope. Move-disabled and copy-disabled: a secret is used in place and dies
// where it was born.
struct ScopedSecret {
    std::string s;
    explicit ScopedSecret(std::string v) : s(std::move(v)) {}
    ~ScopedSecret() { if (!s.empty()) c2w::secure::secure_wipe(&s[0], s.size()); }
    ScopedSecret(const ScopedSecret&) = delete;
    ScopedSecret& operator=(const ScopedSecret&) = delete;
    const std::string& str() const { return s; }
    bool empty() const { return s.empty(); }
};
