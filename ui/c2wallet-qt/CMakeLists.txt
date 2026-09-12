cmake_minimum_required(VERSION 3.21)
project(c2wallet_qt LANGUAGES CXX)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt — the AIR-GAPPED, network-incapable signer (design PR #1621,
# docs/design/c2wallet-qt.md §5.2). This is the OFFLINE, key-bearing side of
# the two-machine model. Its defining security property is defense-in-depth
# layer 1: the signing binary links a deliberately minimal Qt surface so that
# a socket call is a LINK ERROR, not a runtime toggle.
#
#   c2wallet-qt-signer links  Qt6::Core + Qt6::Gui + Qt6::Widgets  ONLY.
#
# It MUST NOT link Qt6::Network, Qt6::WebEngine*, Qt6::WebChannel, libcurl,
# OpenSSL, boost::asio, or any other networking library. Contrast this with the
# sibling ui/c2pool-qt/, which HARD-REQUIRES QtWebEngine (Chromium + a full
# network stack): you cannot embed Chromium and honestly claim to be
# network-incapable, which is exactly why this is a separate binary. We reuse
# c2pool-qt's Widgets shell PATTERN (MainWindow + sidebar + stacked pages),
# never its networked dependencies.
#
# M6 SLICE 1 wires the read/construct flows to the merged offline libraries:
# the Import/Load, Construct+Convert and Scan (Monero view-only) screens call
# the real Qt-free library functions (c2wallet-hdkeys / c2wallet-convert /
# c2wallet_monero). Those libraries link only libsecp256k1 / zlib / the
# vendored Monero crypto — no Qt, no networking — so the signer INHERITS the
# network-incapable property. The signing / tx-build / air-gap-transfer screens
# remain visible stubs (slice 2). No money-path signing UX in this slice.
#
# Install the build deps on Debian/Ubuntu via:
#   sudo apt install qt6-base-dev libsecp256k1-dev zlib1g-dev
# (qt6-base-dev provides Core/Gui/Widgets — NO webengine/webchannel package is
#  needed or wanted here.)
# ═══════════════════════════════════════════════════════════════════════════

# 6.2 is the shared floor with ui/c2pool-qt/. Core/Gui/Widgets are all this
# binary is ever permitted to require.
find_package(Qt6 6.2 REQUIRED COMPONENTS Core Gui Widgets)

set(CMAKE_AUTOMOC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Merged offline libraries the signer links (M6 slice 1) ──────────────────
# All three are deliberately Qt-free and network-free static libraries (see each
# subdir'"'"'s CMakeLists). Adding them here (guarded, so the -DC2WALLET_QT_BUILD_TESTS
# path below does not double-add) lets the signer call the REAL merged functions
# instead of mock-ups. They pull in libsecp256k1 / zlib / the vendored Monero
# crypto only — the network-incapable link-guard (ci/check_no_network.sh) still
# passes, and CI enforces it.
if(NOT TARGET c2wallet-hdkeys)
    add_subdirectory(src/family/bitcoin/hdkeys)
endif()
if(NOT TARGET c2wallet-convert)
    add_subdirectory(src/family/bitcoin/construct)
endif()
if(NOT TARGET c2wallet_monero)
    add_subdirectory(src/family/monero)
endif()

add_executable(c2wallet-qt-signer
    src/main.cpp
    src/shell/MainWindow.cpp
    src/shell/PageImport.cpp
    src/shell/PageConstructConvert.cpp
    src/shell/PageScan.cpp
)

# The wired pages include the C++20 hdkeys/convert public headers; build the
# signer TUs at C++20 too (a superset of the C++17 Monero headers).
set_target_properties(c2wallet-qt-signer PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON)

target_include_directories(c2wallet-qt-signer PRIVATE src)

# The whole security invariant in one place. If a future phase adds
# Qt6::Network / Qt6::WebEngine* / Qt6::WebChannel / a curl / an asio here, the
# ci/check_no_network.sh link-guard (below and in CI) turns red — that is the
# tripwire, and it is deliberate. The three merged libraries linked below are
# Qt-free and network-free, so they do not perturb the guard.
target_link_libraries(c2wallet-qt-signer PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    c2wallet-hdkeys
    c2wallet-convert
    c2wallet_monero
)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt-companion — the ONLINE, KEY-FREE companion (#193), design §5.2.
# The OPPOSITE of the signer: the online side, which MAY link the network. We
# link Qt6::Network here on purpose — the concrete contrast to the signer'"'"'s
# network-incapable link-guard. It still holds NO keys: it links the key-free
# c2wallet-companion library (which links only the M5-A artifact library, hence
# only the vendored SHA-256), NEVER the key-bearing signer core. The mechanical
# proof is ci/check_key_free.sh, registered as a ctest by src/companion.
# ═══════════════════════════════════════════════════════════════════════════
find_package(Qt6 6.2 REQUIRED COMPONENTS Network)

# The key-free companion library + its KATs + the key-free guard.
add_subdirectory(src/companion)

add_executable(c2wallet-qt-companion src/companion/CompanionApp.cpp)
target_include_directories(c2wallet-qt-companion PRIVATE src)
target_link_libraries(c2wallet-qt-companion PRIVATE
    c2wallet-companion
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

# ── Network-incapable link-guard as a ctest ────────────────────────────────
# The same mechanical proof CI runs, available locally: build the target, then
# `ctest` runs ci/check_no_network.sh over the produced binary. Off by default
# so a plain build stays minimal; enable with -DC2WALLET_QT_BUILD_TESTS=ON.
option(C2WALLET_QT_BUILD_TESTS
    "Register the network-incapable link-guard (ci/check_no_network.sh) as a ctest"
    OFF)

if(C2WALLET_QT_BUILD_TESTS)
    enable_testing()

    # M1-A: the Qt-free Bitcoin-script HD-key core and its published-vector KATs
    # (family/bitcoin/hdkeys). It links no Qt and no networking, so it can also be
    # built and tested standalone:
    #   cmake -S ui/c2wallet-qt/src/family/bitcoin/hdkeys -B build-hdkeys -DC2WALLET_QT_BUILD_TESTS=ON
    if(NOT TARGET c2wallet-hdkeys)
        add_subdirectory(src/family/bitcoin/hdkeys)
    endif()

    # M2-A: the Qt-free cross-coin address CONVERT + CONSTRUCT core
    # (family/bitcoin/construct) — the #961-guarded converter and the
    # script-defined output-type encoders. Reuses the #961 engine
    # (core/address_utils) and the BCH CashAddr codec; links the hdkeys library
    # above for the shared btclibs closure. No Qt, no networking; standalone via:
    #   cmake -S ui/c2wallet-qt/src/family/bitcoin/construct -B build-convert -DC2WALLET_QT_BUILD_TESTS=ON
    if(NOT TARGET c2wallet-convert)
        add_subdirectory(src/family/bitcoin/construct)
    endif()

    # M3-A: the Qt-free Bitcoin-script SIGNING core (family/bitcoin/signer)
    # — legacy (SigVersion::BASE) + BIP143 segwit-v0 + wrapped/nested +
    # multi-party combine, self-verify-before-emit. Reuses the vendored
    # dashscript interpreter + system libsecp256k1; no Qt, no networking.
    # Standalone via:
    #   cmake -S ui/c2wallet-qt/src/family/bitcoin/signer -B build-signer -DC2WALLET_QT_BUILD_TESTS=ON
    add_subdirectory(src/family/bitcoin/signer)

    # M5-A: the Qt-free Family-A AIR-GAP TRANSFER ARTIFACTS
    # (family/bitcoin/artifact) — the PSBT-like unsigned container
    # (online->offline), the c2pool-loader signed container (offline->online,
    # one raw hex per line), the multi-frame QR codec, and the validate-seam
    # contract. It MARSHALS bytes (does not sign); reuses only the vendored
    # btclibs SHA-256 for the sha256/sha256d digests. No Qt, no networking;
    # standalone via:
    #   cmake -S ui/c2wallet-qt/src/family/bitcoin/artifact -B build-artifact -DC2WALLET_QT_BUILD_TESTS=ON
    if(NOT TARGET c2wallet-artifact)
        add_subdirectory(src/family/bitcoin/artifact)
    endif()

    add_test(
        NAME no_network_link_guard
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/ci/check_no_network.sh"
                "$<TARGET_FILE:c2wallet-qt-signer>"
    )

    # ── Family B (Monero) seed/key/address core (M1-X) ──────────────────────
    # Qt-FREE static lib + KAT executable (c2wallet-monero-seed-test). It links
    # the vendored Monero crypto directly, not Qt, so the money-correctness KATs
    # build and run without the signer app. See src/family/monero/CMakeLists.txt.
    if(NOT TARGET c2wallet_monero)
        add_subdirectory(src/family/monero)
    endif()
endif()
