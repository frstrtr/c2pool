[![Total alerts](https://img.shields.io/lgtm/alerts/g/frstrtr/c2pool.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/frstrtr/c2pool/alerts/)

# c2pool - p2pool rebirth in c++
(started 02.02.2020)

based on Forrest Voight (https://github.com/forrestv) concept and python code (https://github.com/p2pool/p2pool)

Bitcoin wiki page - https://en.bitcoin.it/wiki/P2Pool

Bitcointalk forum thread - https://bitcointalk.org/index.php?topic=18313

Some technical details - https://bitcointalk.org/index.php?topic=457574


<details>
  
  <summary>Donations towards further development of с2pool implementation in C++</summary>

  
BTC:

### 1C2PooLktmeKwx7Sp7aRoDiyUy3y7TMofw

PayPal donation:

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=9DF676HUWAHKY)

![image](https://github.com/frstrtr/c2pool/assets/4164913/51e82162-3d0b-435a-89b7-d8051983b3dc)


</details>

Telegram:

### https://t.me/c2pool

Discord:

### https://discord.gg/yb6ujsPRsv

# Install:
CMake:
```
sudo apt remove --purge --auto-remove cmake
sudo apt update
sudo apt install -y software-properties-common lsb-release
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null
sudo apt-add-repository "deb https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main"
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 6AF7F09730B3F0A4
sudo apt update
sudo apt install cmake
```
<!-- c2pool
```

sudo apt-get update
sudo apt-get install libleveldb-dev
sudo apt install gcc-8 g++-8
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 800 --slave /usr/bin/g++ g++ /usr/bin/g++-8
sudo apt-get install -yq libboost-filesystem1.71-dev && sudo apt-get install -yq libboost1.71-all-dev
sudo apt install git

git clone https://github.com/frstrtr/c2pool.git
cd c2pool
git pull
mkdir cmake-build-debug
cmake -DCMAKE_BUILD_TYPE=Debug -S . -B cmake-build-debug
cmake --build cmake-build-debug --target c2pool_main -j 6
``` -->
c2pool
```
apt update && apt upgrade

apt install wget

apt install g++-9
update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 900 --slave /usr/bin/g++ g++ /usr/bin/g++-9

wget -O boost_1_71_0.tar.gz https://boostorg.jfrog.io/artifactory/main/release/1.71.0/source/boost_1_71_0.tar.gz
tar xzvf boost_1_71_0.tar.gz
cd boost_1_71_0/
./bootstrap.sh --prefix=/usr/
./b2
./b2 install
cd ..

apt install git
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
mkdir cmake-build-debug
cmake -DCMAKE_BUILD_TYPE=Debug -S . -B cmake-build-debug
cmake --build cmake-build-debug --target c2pool_main -j 6
```

launch
```
cd cmake-build-debug
./c2pool_main --networks=dgb
```
