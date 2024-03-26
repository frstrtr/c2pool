| Name      | Version|
|-----------|--------|
| CMake     | >= 3.22|
| OpenSSL   | >= 3.xx|
| GCC       | 9      |
| Boost     | 1.78   |

> [!WARNING]
> While compiling you may get an error like:
> c++: internal compiler error: Killed (program cc1plus)


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