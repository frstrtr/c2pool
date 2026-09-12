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
# M0 is the foundation phase: no keys, no signing, no crypto yet. It stands up
# the tree, the Widgets-only skeleton, and the mechanical proof of the
# network-incapable property (ci/check_no_network.sh, enforced in CI).
#
# Install the build deps on Debian/Ubuntu via:
#   sudo apt install qt6-base-dev
# (qt6-base-dev provides Core/Gui/Widgets — NO webengine/webchannel package is
#  needed or wanted here.)
# ═══════════════════════════════════════════════════════════════════════════

# 6.2 is the shared floor with ui/c2pool-qt/. Core/Gui/Widgets are all this
# binary is ever permitted to require.
find_package(Qt6 6.2 REQUIRED COMPONENTS Core Gui Widgets)

set(CMAKE_AUTOMOC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(c2wallet-qt-signer
    src/main.cpp
    src/shell/MainWindow.cpp
)

target_include_directories(c2wallet-qt-signer PRIVATE src)

# The whole security invariant in one place. If a future phase adds
# Qt6::Network / Qt6::WebEngine* / Qt6::WebChannel / a curl / an asio here, the
# ci/check_no_network.sh link-guard (below and in CI) turns red — that is the
# tripwire, and it is deliberate.
target_link_libraries(c2wallet-qt-signer PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt-companion — the ONLINE, KEY-FREE companion (#193), design §5.2.
# The OPPOSITE of the signer: the online side, which MAY link the network. We
# link Qt6::Network here on purpose — the concrete contrast to the signer's
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
    add_subdirectory(src/family/bitcoin/hdkeys)

    # M2-A: the Qt-free cross-coin address CONVERT + CONSTRUCT core
    # (family/bitcoin/construct) — the #961-guarded converter and the
    # script-defined output-type encoders. Reuses the #961 engine
    # (core/address_utils) and the BCH CashAddr codec; links the hdkeys library
    # above for the shared btclibs closure. No Qt, no networking; standalone via:
    #   cmake -S ui/c2wallet-qt/src/family/bitcoin/construct -B build-convert -DC2WALLET_QT_BUILD_TESTS=ON
    add_subdirectory(src/family/bitcoin/construct)

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
endif()
