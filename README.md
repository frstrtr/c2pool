[![Total alerts](https://img.shields.io/lgtm/alerts/g/frstrtr/c2pool.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/frstrtr/c2pool/alerts/)

# c2pool - p2pool rebirth in c++
(started 02.02.2020)

based on Forrest Voight (https://github.com/forrestv) concept and python code (https://github.com/p2pool/p2pool)

Bitcoin wiki page - https://en.bitcoin.it/wiki/P2Pool

Bitcointalk forum thread - https://bitcointalk.org/index.php?topic=18313

Some technical details - https://bitcointalk.org/index.php?topic=457574

p2pool sharechain based temporal levelled blockchain DEX/mining pool/hr marketplace and more... written in c++ using LevelDB.

![Time Hybrid Evaluation](/doc/concepts/THE%20coin.png)
Time Hybrid Evaluation coin (THE coin - (experimental feature)) for node maintainers/owners

<details>
  
  <summary>Donations towards further development of с2pool implementation in C++</summary>

  
BTC:

### 1C2PooLktmeKwx7Sp7aRoDiyUy3y7TMofw

DGB:

### DJKrhVNZtTggUFHJ4CKCkmyWDSRUewyqm3

Dogecoin:

### DNJx6HYka3mncLBaw1TLUARtXxe2BgjHf6

Chia (XCH):

### xch120duz2pn97053lrd0ym4vxqe4hlv2awslc9pf4ld5vf7nvagv46s2t0azk

</details>

Telegram:

### t.me/c2pool

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
c2pool
```

sudo apt-get update
sudo apt-get install libleveldb-dev
sudo apt install gcc-8 g++-8
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 800 --slave /usr/bin/g++ g++ /usr/bin/g++-8
sudo apt-get install -yq libboost-filesystem1.71-dev && sudo apt-get install -yq libboost1.71-all-dev

https://github.com/frstrtr/c2pool.git
cd c2pool
mkdir cmake-build-debug
cmake -DCMAKE_BUILD_TYPE=Debug -S . -B /cmake-build-debug
cmake --build /cmake-build-debug --target coind_worker -j 3
```
