# Build environment for the OSS Scanner security service. The enrolment itself is
# projects/c2pool/project.yaml in the oss-scanner repository.
#
# The scanner builds this image with the repository as the build context and network
# access, then runs its audit inside the finished image with NO network. Everything
# the build and the tests need is therefore fetched here.
#
# Mirrors the "Linux x86_64" job in .github/workflows/build.yml: Ubuntu 24.04, GCC 13
# (the build-essential default on noble),
# Conan 2 with the committed ci/conan/linux-gcc13.profile. Two deliberate differences:
#   - -g1 -fno-omit-frame-pointer, so crashes found by the scanner symbolize cleanly
#     (line tables only: far less debug info than -g, so compile and link stay fast);
#   - Ninja instead of Make, so the test build can keep going past a broken target.
#
# Build budget: the scanner allows 45 minutes from clone to finished image on 16 cpu.
# Only the daemons and a named set of parser-heavy tests are built here; everything
# else can be built offline inside the image, because the Conan cache is complete.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential cmake ninja-build pkg-config git \
      python3 python3-venv python3-pip libsecp256k1-dev \
    && rm -rf /var/lib/apt/lists/*

# Conan 2 in a venv (Ubuntu 24.04 refuses a system-wide pip install).
RUN python3 -m venv /opt/conan \
    && /opt/conan/bin/pip install --no-cache-dir "conan>=2.0,<3.0" \
    && ln -s /opt/conan/bin/conan /usr/local/bin/conan
ENV CONAN_HOME=/opt/conan-home

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Resolve the Conan dependencies (boost, nlohmann_json, yaml-cpp, gtest, leveldb,
# zeromq). conancenter ships gcc-13 prebuilts for this profile, so this is a download,
# not a Boost build. The second, --no-remote install proves the cache is complete for
# the offline scan.
RUN for attempt in 1 2 3; do \
      conan install . -pr:a=ci/conan/linux-gcc13.profile --build=missing --output-folder=build && break; \
      echo "conan install failed (attempt $attempt/3)"; sleep $((attempt * 15)); \
    done \
    && conan install . -pr:a=ci/conan/linux-gcc13.profile --build=missing --output-folder=build -nr

# CMAKE_BUILD_TYPE stays Release: Conan's CMakeDeps only maps the Release config of
# the dependencies, so RelWithDebInfo would not link. Debug info comes from the flags.
RUN cmake -S . -B build -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-g1 -fno-omit-frame-pointer" \
      -DCMAKE_CXX_FLAGS="-g1 -fno-omit-frame-pointer" \
      -DCOIN_DGB=ON \
      -DXMR_BUILD_RANDOMX=ON \
      -DXMR_BUILD_OPTION_B_KATS=ON

# The per-coin pool daemons are what operators run; a failure here fails the image.
RUN cmake --build build -j"$(nproc)" --target \
      c2pool c2pool-ltc c2pool-btc c2pool-dgb c2pool-bch c2pool-dash c2pool-bip110

# Parser-heavy unit tests and known-answer tests (KATs), which make good drivers for
# the scanner: stratum, share and p2p messages, core, sharechain, and the XMR wire and
# levin fuzz KATs. Targets that this configuration does not define are skipped, so a
# renamed test never fails the image. Keep going past a broken target, and stop well
# inside the build budget. No ctest here: it costs budget and proves nothing the
# scanner needs.
RUN wanted="test_stratum_extensions test_stratum_interim_hardening \
      test_share_messages test_dash_p2p_messages test_dash_poolnode_messages \
      core_test sharechain_test \
      xmr_levin_fuzz_kat xmr_native_blob_reader_fuzz_kat xmr_wire_dos_check"; \
    known="$(ninja -C build -t targets all | cut -d: -f1)"; \
    targets=""; \
    for t in $wanted; do \
      if printf "%s\n" "$known" | grep -qx "$t"; then targets="$targets $t"; \
      else echo "NOTE: test target $t is not defined, skipped"; fi; \
    done; \
    timeout 600 ninja -C build -k 0 -j"$(nproc)" $targets \
    || echo "WARNING: some test targets did not build (or the build hit its time limit)"
