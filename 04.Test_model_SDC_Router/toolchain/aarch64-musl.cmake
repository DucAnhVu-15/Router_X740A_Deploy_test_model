# CMake toolchain cho router VNPT: aarch64, musl, link tĩnh.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(TC_ROOT "$ENV{HOME}/sdc-router/toolchains/aarch64--musl--stable-2024.05-1")
set(TC_PREFIX "${TC_ROOT}/bin/aarch64-buildroot-linux-musl-")

set(CMAKE_C_COMPILER "${TC_PREFIX}gcc")
set(CMAKE_CXX_COMPILER "${TC_PREFIX}g++")
set(CMAKE_AR "${TC_PREFIX}ar" CACHE FILEPATH "")
set(CMAKE_RANLIB "${TC_PREFIX}ranlib" CACHE FILEPATH "")
set(CMAKE_STRIP "${TC_PREFIX}strip" CACHE FILEPATH "")

set(CMAKE_FIND_ROOT_PATH "${TC_ROOT}/aarch64-buildroot-linux-musl/sysroot")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
