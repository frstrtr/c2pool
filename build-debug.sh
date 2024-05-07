mkdir build
cd build
conan install .. --build=missing --output-folder=. --settings=build_type=Debug
cmake .. --preset conan-debug
cmake --build .