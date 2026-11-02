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
# KeyScan.hpp, the signer): see SweepPlan.hpp. The btclibs closure (base58,
# sha256, the hdkeys hex/JSON leaf helpers) comes through c2wallet-hdkeys
# PRIVATE, as for c2wallet-dash-common; static linking pulls only the objects
# these files reference, and ci/check_key_free.sh over the archive and over the
# binaries that link it proves no key or signing symbol is among them.
# ═══════════════════════════════════════════════════════════════════════════

if(NOT TARGET c2wallet-hdkeys)
    # The hdkeys KATs belong to the signer-side build; a companion-only
    # configure that reaches this file only needs the library itself.
    set(_c2w_dash_plan_saved_tests "${C2WALLET_QT_BUILD_TESTS}")
    set(C2WALLET_QT_BUILD_TESTS OFF)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../hdkeys ${CMAKE_BINARY_DIR}/_dash_plan_hdkeys)
    set(C2WALLET_QT_BUILD_TESTS "${_c2w_dash_plan_saved_tests}")
    unset(_c2w_dash_plan_saved_tests)
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
target_link_libraries(c2wallet-dash-plan PRIVATE c2wallet-hdkeys)
