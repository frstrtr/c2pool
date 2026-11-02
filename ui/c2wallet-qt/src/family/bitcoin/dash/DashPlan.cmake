# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-dash-plan — the KEY-FREE DASH plan library (scan & plan slice S-A).
#
# Included by this directory's CMakeLists.txt (the signer-side DASH libraries)
# and by src/companion/CMakeLists.txt (the online companion), so the companion
# can plan exactly what the offline signer plans without building or linking
# any key code. Guard the include with if(NOT TARGET c2wallet-dash-plan).
#
#   DashAddress.cpp     base58check / hash160 decode / P2PKH script (no key)
#   UtxoIntake.cpp      UTXO JSON intake, screening, maturity at a height
#   SweepPlan.cpp       plan_sweep, the unsigned serializer, size estimate,
#                       loader-file emit
#   InjectManifest.cpp  the <name>.manifest.json writer + sha256 digests
#   GovCollateral.cpp   gobject collateral hash + OP_RETURN script (no key)
#
# Its headers are std-only and none declares or includes a key type (FoundKey,
# KeyScan.hpp, the signer): see SweepPlan.hpp. ci/check_key_free.sh over the
# archive and over the binaries that link it proves no key or signing symbol
# is among the objects it pulls in.
#
# Its .cpp files need only leaf helpers: the hdkeys hex and JSON readers and
# the btclibs base58 / hash / sha256 closure. When c2wallet-hdkeys exists (the
# full ui/c2wallet-qt tree, the DASH standalone build) those come from it,
# PRIVATE, as for c2wallet-dash-common; static linking pulls only the
# referenced objects. A companion-only configure has no hdkeys target and
# builds c2wallet-dash-plan-leaf instead: the same leaf sources and include
# tree, no libsecp256k1 and no zlib, so it needs neither dev package.
# ═══════════════════════════════════════════════════════════════════════════

if(TARGET c2wallet-hdkeys)
    set(_c2w_dash_plan_helpers c2wallet-hdkeys)
else()
    get_filename_component(_c2w_root "${CMAKE_CURRENT_LIST_DIR}/../../../../../.." ABSOLUTE)
    add_library(c2wallet-dash-plan-leaf STATIC
        ${CMAKE_CURRENT_LIST_DIR}/../hdkeys/HexUtil.cpp
        ${CMAKE_CURRENT_LIST_DIR}/../hdkeys/MiniJson.cpp
        ${_c2w_root}/src/btclibs/crypto/sha256.cpp
        ${_c2w_root}/src/btclibs/crypto/sha512.cpp
        ${_c2w_root}/src/btclibs/crypto/ripemd160.cpp
        ${_c2w_root}/src/btclibs/crypto/hmac_sha512.cpp
        ${_c2w_root}/src/btclibs/crypto/hmac_sha256.cpp
        ${_c2w_root}/src/btclibs/base58.cpp
        ${_c2w_root}/src/btclibs/hash.cpp
        ${_c2w_root}/src/btclibs/uint256.cpp
        ${_c2w_root}/src/btclibs/util/strencodings.cpp
        ${_c2w_root}/src/btclibs/util/str.cpp
    )
    set_target_properties(c2wallet-dash-plan-leaf PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
    # The include tree c2wallet-hdkeys publishes, without its libraries.
    target_include_directories(c2wallet-dash-plan-leaf PUBLIC
        ${_c2w_root}/src ${_c2w_root}/src/btclibs ${_c2w_root}/src/btclibs/util
        ${_c2w_root}/src/btclibs/crypto ${_c2w_root}/src/btclibs/compat)
    set(_c2w_dash_plan_helpers c2wallet-dash-plan-leaf)
    unset(_c2w_root)
endif()

add_library(c2wallet-dash-plan STATIC
    ${CMAKE_CURRENT_LIST_DIR}/DashAddress.cpp
    ${CMAKE_CURRENT_LIST_DIR}/UtxoIntake.cpp
    ${CMAKE_CURRENT_LIST_DIR}/SweepPlan.cpp
    ${CMAKE_CURRENT_LIST_DIR}/InjectManifest.cpp
    ${CMAKE_CURRENT_LIST_DIR}/GovCollateral.cpp
)
set_target_properties(c2wallet-dash-plan PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_include_directories(c2wallet-dash-plan PUBLIC ${CMAKE_CURRENT_LIST_DIR})
# PRIVATE on purpose (same reason as c2wallet-dash-common): the .cpp files need
# the btclibs include tree, the headers are std-only, and btclibs must not leak
# into a dashscript translation unit.
target_link_libraries(c2wallet-dash-plan PRIVATE ${_c2w_dash_plan_helpers})
unset(_c2w_dash_plan_helpers)
