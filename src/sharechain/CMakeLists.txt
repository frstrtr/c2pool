
file(GLOB legacy_tracker "legacy/*.hpp")

set(SHARECHAIN_SOURCE
    share.hpp
    sharechain.cpp sharechain.hpp
    ${legacy_tracker}
)

add_library(sharechain STATIC ${SHARECHAIN_SOURCE})
target_link_libraries(sharechain core)

add_subdirectory(test)