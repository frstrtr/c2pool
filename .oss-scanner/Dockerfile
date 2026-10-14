# Build environment for the OSS Scanner security service. The enrolment itself is
# projects/c2pool/project.yaml in the oss-scanner repository.
#
# The scanner builds this image with the repository as the build context and network
# access, then runs its audit inside the finished image with NO network. Everything
# the build and the tests need is therefore fetched here.
#
# Mirrors the "Linux x86_64" job in .github/workflows/build.yml: Ubuntu 24.04, GCC 13,
# Conan 2 with the committed ci/conan/linux-gcc13.profile. Two deliberate differences:
#   - -g -fno-omit-frame-pointer, so crashes found by the scanner symbolize cleanly;
#   - Ninja instead of Make, so the test build can keep going past a broken target.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential gcc-13 g++-13 cmake ninja-build pkg-config git \
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
      -DCMAKE_C_FLAGS="-g -fno-omit-frame-pointer" \
      -DCMAKE_CXX_FLAGS="-g -fno-omit-frame-pointer" \
      -DCOIN_DGB=ON \
      -DXMR_BUILD_RANDOMX=ON \
      -DXMR_BUILD_OPTION_B_KATS=ON

# The per-coin pool daemons are what operators run; a failure here fails the image.
RUN cmake --build build -j"$(nproc)" --target \
      c2pool c2pool-ltc c2pool-btc c2pool-dgb c2pool-bch c2pool-dash c2pool-bip110

# Everything else: the unit tests and known-answer tests (KATs), which make good
# drivers for the parsers. Keep going past a broken target and stay inside the
# scanner's build time limit, so one stray target never costs the whole image.
RUN timeout 1800 ninja -C build -k 0 -j"$(nproc)" \
    || echo "WARNING: some test targets did not build (or the build hit its time limit)"

# Run the fast tests so the log shows the image works, without letting a failure
# abort it. LiveTest.* needs a coin daemon and the soak tests run for minutes.
RUN cd build && (ctest --output-on-failure -j"$(nproc)" --timeout 120 \
      --exclude-regex "LiveTest\.|soak" \
    || echo "WARNING: ctest reported failures")
