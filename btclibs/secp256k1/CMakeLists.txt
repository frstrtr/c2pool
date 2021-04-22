#project(secp256k1)

#file(GLOB include_sources "include/*.h" "include/*.c")
set(include_sources include/secp256k1_ecdh.h include/secp256k1_extrakeys.h)
file(GLOB src_sources "src/*.h" "src/*.c")

message(${include_sources})
#message(${src_sources})
add_library(secp256k1 STATIC ${include_sources} ${src_sources})

target_include_directories(secp256k1 PUBLIC include src)