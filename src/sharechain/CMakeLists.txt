
file(GLOB legacy_tracker "legacy/*.hpp")

set(SHARECHAIN_SOURCE
    share.hpp
    sharechain.cpp sharechain.hpp
    prepared_list.hpp
    ${legacy_tracker}
)

add_library(sharechain OBJECT ${SHARECHAIN_SOURCE})
target_link_libraries(sharechain core)

add_subdirectory(test)
add_subdirectory(v37/test)
