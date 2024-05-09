cmake:
```
sudo snap install cmake --channel=3.24/stable --classic
```

conan:
```
mkdir build && cd build
conan install .. --build=missing --output-folder=. --settings=build_type=Debug
cmake .. --preset conan-debug
cmake --build .
```

