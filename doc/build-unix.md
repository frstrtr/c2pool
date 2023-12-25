required openssl >= 3

```shell
sudo apt update & apt upgrade
sudo apt install wget
sudo apt install git

sudo apt install g++-9
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 900 --slave /usr/bin/g++ g++ /usr/bin/g++-9

sudo apt install cmake
sudo apt-get install libsnappy-dev libleveldb-dev
sudo apt install qt6-base-dev
```

install boost 1.78.0:
```shell
wget -O boost_1_78_0.tar.gz https://boostorg.jfrog.io/artifactory/main/release/1.78.0/source/boost_1_78_0.tar.gz
tar xzvf boost_1_78_0.tar.gz
cd boost_1_78_0
./bootstrap.sh --prefix=/usr/
./b2
sudo ./b2 install
cd ..
```

install c2pool:
```shell
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
mkdir build
cmake -DCMAKE_BUILD_TYPE=Debug -S . -B build
cmake --build build --target c2pool_main -j 6
```

run:
```shell
cd build/c2pool
./c2pool_main --web_server=0.0.0.0:8083
```