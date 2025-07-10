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
| GCC       | 9      |
| Boost     | 1.78   |

# Instruction

```shell
sudo apt update & apt upgrade
sudo apt install wget
sudo apt install git

sudo apt install g++-9
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 900 --slave /usr/bin/g++ g++ /usr/bin/g++-9

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
# Download from SourceForge (JFrog Artifactory is no longer available)
wget https://sourceforge.net/projects/boost/files/boost/1.78.0/boost_1_78_0.tar.bz2
tar xjvf boost_1_78_0.tar.bz2
cd boost_1_78_0
./bootstrap.sh --prefix=/usr/
sudo ./b2 install
cd ..
```

install c2pool:

```shell
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
mkdir build
# Force CMake to use the newly installed Boost 1.78.0
cmake -DCMAKE_BUILD_TYPE=Debug -DBoost_ROOT=/usr/ -DBoost_NO_SYSTEM_PATHS=ON -S . -B build
cmake --build build --target c2pool_main -j 6
```

Essential to build default config.cfg file!
UI Config:

```shell
cd build/c2pool
./c2pool_main --ui_config
```

Configure RPC credentials manually:

```shell
cd build/c2pool
# Create network config directory (for testnet)
mkdir -p tLTC

# Create config file with your Litecoin node RPC credentials
cat > tLTC/config.cfg << EOF
[General]
testnet=true
address=
numaddresses=2
timeaddresses=172800

[coind]
coind-address=127.0.0.1
coind-p2p-port=19335
coind-config-path=
coind-rpc-ssl=false
coind-rpc-port=19332
coind_rpc_userpass=YOUR_RPC_USERNAME:YOUR_RPC_PASSWORD

[pool]
c2pool_port=3037
max_conns=40
outgoing_conns=6
max_attempts=10

[worker]
worker_port=5027
fee=0
EOF

# Edit the config file to add your actual RPC credentials
nano tLTC/config.cfg
```

Get RPC credentials from your Litecoin node:

```shell
# Check your Litecoin config file for RPC credentials
cat ~/.litecoin/litecoin.conf | grep -E "rpcuser|rpcpassword"
```

Run:

```shell
cd build/c2pool
./c2pool_main --web_server=0.0.0.0:8083
```