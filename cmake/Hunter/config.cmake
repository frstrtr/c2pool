# Template for a custom hunter configuration Useful when there is a need for a
# non-default version or arguments of a dependency, or when a project not
# registered in soramitsu-hunter should be added.
#
# hunter_config( package-name VERSION 0.0.0-package-version CMAKE_ARGS
# "CMAKE_VARIABLE=value" )
#
# hunter_config( package-name URL https://repo/archive.zip SHA1
# 1234567890abcdef1234567890abcdef12345678 CMAKE_ARGS "CMAKE_VARIABLE=value" )

#message("22HUNTER_Boost_VERSION = ${HUNTER_Boost_VERSION} | ${HUNTER_ROOT}")
#SET(HUNTER_ROOT ${CMAKE_CURRENT_BINARY_DIR}/hunter)
#message("22.2HUNTER_Boost_VERSION = ${HUNTER_Boost_VERSION} | ${HUNTER_ROOT}")
#hunter_config(
#        Boost
#        VERSION 1.71.0-p0
#)

#message("33HUNTER_Boost_VERSION = ${HUNTER_Boost_VERSION} | ${HUNTER_ROOT}")