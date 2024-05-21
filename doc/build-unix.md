> [!WARNING]
> While compiling you may get an error like:\
> `c++: internal compiler error: Killed (program cc1plus)`\
> \
> Reasons:
> 1. Low ram/swap. Increase ram/swap or decrease the amount of make -j to 1 (more compile threads -> more mem usage).
> 2. SELinux/grsecurity/Hardened kernel: Kernels that use ASLR as a security measure tend to mess up GCC's precompiled header implementation. Try using an unhardened kernel (without ASLR), or compiling using clang, or gcc without pch. (you can get this issue when using OVH hosting).


# Dependencies
| Name      | Version|
|-----------|--------|
| CMake     | >= 3.22|
| OpenSSL   | >= 3.xx|
| GCC       | 11     |
| Boost     | 1.78   |

# Instruction
```shell
sudo apt update & apt upgrade
sudo apt install wget
sudo apt install git

sudo apt install g++-11
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 1100 --slave /usr/bin/g++ g++ /usr/bin/g++-11

sudo apt install cmake
sudo apt install make
sudo apt-get install libleveldb-dev
sudo apt install qt6-base-dev
```

If ui config is needed:
```shell
sudo apt-get install libgl1-mesa-dev
```

install boost 1.78.0:
```shell
wget -O boost_1_78_0.tar.gz https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.gz
tar xzvf boost_1_78_0.tar.gz
cd boost_1_78_0
./bootstrap.sh --prefix=/usr/
sudo ./b2 install
```

install c2pool:
```shell
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
mkdir build
cmake -DCMAKE_BUILD_TYPE=Debug -S . -B build
cmake --build build --target c2pool_main -j 6
```

UI Config:
```shell
./c2pool_main --ui_config
```

Run:
```shell
cd build/c2pool
./c2pool_main --web_server=0.0.0.0:8083
```